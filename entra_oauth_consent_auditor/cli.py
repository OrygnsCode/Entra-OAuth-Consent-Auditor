import argparse
import os
import sys
import json
import logging
import json
import logging
import traceback
from dotenv import load_dotenv

from . import __version__
from .auth import get_graph_token
from .graph import GraphClient
from .audit import Auditor, DEFAULT_RISKY_SCOPES, DEFAULT_RISKY_ROLES
from .report import write_csv, write_json

# Setup basic logging
logging.basicConfig(level=logging.WARN, format='%(message)s')
logger = logging.getLogger("entra_oauth_consent_auditor")

def load_json_list(path):
    if not path:
        return None
    try:
        with open(path, 'r') as f:
            data = json.load(f)
            if isinstance(data, list):
                return set(data)
            # If it's a dict, maybe keys? But let's assume list of strings as per typical use.
            logger.warning(f"{path} content is not a list. Ignoring.")
            return None
    except Exception as e:
        logger.error(f"Failed to load JSON from {path}: {e}")
        sys.exit(1)

def main():
    load_dotenv()
    
    parser = argparse.ArgumentParser(
        description=f"Entra OAuth Consent Auditor v{__version__} - Audit delegated grants and app role assignments.",
        prog="entra-oauth-consent-auditor"
    )
    
    parser.add_argument("--version", action="version", version=f"%(prog)s {__version__}")
    
    parser.add_argument("--output-dir", default="out", help="Directory to save reports (default: out)")
    parser.add_argument("--format", default="both", choices=["csv", "json", "both"], help="Output format (default: both)")
    
    parser.add_argument("--only-risky", action="store_true", help="Report only findings with risky scopes/roles")
    parser.add_argument("--fail-on-risk", action="store_true", help="Exit with code 2 if any risky findings are detected")
    
    # Intentionally string defaults to allow logic to handle defaults
    # Intentionally store_true for "no" flags to be safe defaults
    parser.add_argument("--no-app-roles", action="store_true", help="Skip App Role Assignments")
    parser.add_argument("--no-delegated", action="store_true", help="Skip Delegated Grants")
    
    parser.add_argument("--risk-scopes-json", help="Path to JSON file containing list of risky delegated scopes")
    parser.add_argument("--risk-roles-json", help="Path to JSON file containing list of risky app roles")
    
    parser.add_argument("--quiet", action="store_true", help="Suppress output")
    parser.add_argument("--debug", action="store_true", help="Enable debug logging")

    args = parser.parse_args()
    
    # Configure logging
    if args.debug:
        logger.setLevel(logging.DEBUG)
        logging.getLogger().setLevel(logging.DEBUG)
    elif args.quiet:
        logger.setLevel(logging.CRITICAL) # Silence mostly everything
    else:
        logger.setLevel(logging.INFO)

    # Validate inputs
    include_app = not args.no_app_roles
    include_delegated = not args.no_delegated
    
    # Get credentials
    tenant_id = os.environ.get("TENANT_ID")
    client_id = os.environ.get("CLIENT_ID")
    client_secret = os.environ.get("CLIENT_SECRET")
    
    if not all([tenant_id, client_id, client_secret]):
        logger.error("Missing required environment variables: TENANT_ID, CLIENT_ID, CLIENT_SECRET.")
        logger.error("Please verify your .env file.")
        sys.exit(1)

    try:
        token = get_graph_token(tenant_id, client_id, client_secret)
    except Exception as e:
        logger.error(str(e))
        sys.exit(1)

    client = GraphClient(token)
    
    risky_scopes = load_json_list(args.risk_scopes_json)
    risky_roles = load_json_list(args.risk_roles_json)
    
    auditor = Auditor(client, risky_scopes=risky_scopes, risky_roles=risky_roles)
    
    findings = []
    
    if include_delegated:
        try:
            findings.extend(auditor.audit_delegated_grants())
        except KeyboardInterrupt:
            logger.info("Audit interrupted by user.")
            sys.exit(130)
        except Exception as e:
            logger.error(f"Error auditing delegated grants: {e}")
        except Exception as e:
            logger.error(f"Error auditing delegated grants: {e}")
            if args.debug:
                traceback.print_exc()
    
    if include_app:
        try:
            findings.extend(auditor.audit_app_roles())
        except KeyboardInterrupt:
            logger.info("Audit interrupted by user.")
            sys.exit(130)
        except Exception as e:
            logger.error(f"Error auditing app roles: {e}")
            if args.debug:
                traceback.print_exc()

    # Filter if only-risky
    if args.only_risky:
        logger.info("Filtering for only risky findings...")
        findings = [f for f in findings if f.get("RiskyCount", 0) > 0]
        
    logger.info(f"Total findings: {len(findings)}")
    
    # Generate Reports
    if args.format in ["csv", "both"]:
        path = write_csv(findings, args.output_dir)
        logger.info(f"CSV Report: {path}")
        
    if args.format in ["json", "both"]:
        path = write_json(findings, tenant_id, args.output_dir, version=__version__)
        logger.info(f"JSON Report: {path}")

    # Check for fail condition
    risky_count = sum(1 for f in findings if f.get("RiskyCount", 0) > 0)
    if args.fail_on_risk and risky_count > 0:
        logger.warning(f"FAIL: {risky_count} risky findings detected.")
        sys.exit(2)
        
    logger.info("Audit complete.")

if __name__ == "__main__":
    main()
