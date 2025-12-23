import csv
import json
import os
from typing import List, Dict
from datetime import datetime, timezone

def ensure_output_dir(path: str):
    if not os.path.exists(path):
        os.makedirs(path)

# Common fieldnames for consistent schema
FIELDNAMES = [
    "FindingType", "ClientDisplayName", "ClientAppId", "ClientSpId",
    "ResourceDisplayName", "ResourceAppId", "ResourceSpId",
    "PrincipalDisplayName", "PrincipalUPN", "PrincipalId",
    "ConsentType", "Scopes", "RiskyItems", "RiskyCount",
    "RiskReason", "RiskNotes",
    "CreatedDateTime", "ExpiryTime", "ClientPublisher"
]

def write_csv(findings: List[Dict], output_dir: str, filename: str = "entra_oauth_consent_auditor.csv"):
    ensure_output_dir(output_dir)
    filepath = os.path.join(output_dir, filename)
    
    # Sort copy to avoid in-place mutation of the original list if reused elsewhere
    # FindingType then ClientDisplayName then ResourceDisplayName then PrincipalUPN then Scopes
    sorted_findings = sorted(findings, key=lambda x: (
        x.get("FindingType", ""),
        x.get("ClientDisplayName", "") or "",
        x.get("ResourceDisplayName", "") or "",
        x.get("PrincipalUPN", "") or "",
        x.get("Scopes", "") or ""
    ))
    
    with open(filepath, 'w', newline='', encoding='utf-8') as f:
        writer = csv.DictWriter(f, fieldnames=FIELDNAMES)
        writer.writeheader()
        for finding in sorted_findings:
            # Normalize dict: if value is None, use ""; only use known fields
            row = {k: (finding.get(k) or "") for k in FIELDNAMES}
            writer.writerow(row)
            
    return filepath

def write_json(findings: List[Dict], tenant_id: str, output_dir: str, filename: str = "entra_oauth_consent_auditor.json", version: str = "Unknown"):
    ensure_output_dir(output_dir)
    filepath = os.path.join(output_dir, filename)
    
    # Calculate summary robustly (handle potential str/int types by safe casting)
    def safe_risk_count(f):
        val = f.get("RiskyCount", 0)
        try:
            return int(val)
        except (ValueError, TypeError):
            return 0

    total_findings = len(findings)
    risky_findings = sum(1 for f in findings if safe_risk_count(f) > 0)
    
    # Distinguish types
    delegated = [f for f in findings if f.get("FindingType") == "DELEGATED_GRANT"]
    app_roles = [f for f in findings if f.get("FindingType") == "APP_ROLE_ASSIGNMENT"]
    
    summary = {
        "total_findings": total_findings,
        "risky_findings": risky_findings,
        "total_delegated_grants": len(delegated),
        "risky_delegated_grants": sum(1 for f in delegated if safe_risk_count(f) > 0),
        "total_app_role_assignments": len(app_roles),
        "risky_app_role_assignments": sum(1 for f in app_roles if safe_risk_count(f) > 0)
    }
    
    # Deterministic Sort (avoid in-place mutation)
    sorted_findings = sorted(findings, key=lambda x: (
        x.get("FindingType", ""),
        x.get("ClientDisplayName", "") or "",
        x.get("ResourceDisplayName", "") or "",
        x.get("PrincipalUPN", "") or "",
        x.get("Scopes", "") or ""
    ))

    # Normalize None to empty strings in JSON findings too for cleanliness
    # But for JSON, maybe we just want to output what we have? 
    # Requirement: "If any finding field is None... use """
    # We will create a clean list for JSON output.
    json_findings = []
    for f in sorted_findings:
        # We generally keep all keys present in the dict, but ensure values aren't None
        clean_f = {k: (v if v is not None else "") for k, v in f.items()}
        json_findings.append(clean_f)

    output = {
        "metadata": {
            "toolName": "entra_oauth_consent_auditor",
            "toolVersion": version,
            "tenantId": tenant_id,
            "runTimestampUtc": datetime.now(timezone.utc).isoformat()
        },
        "summary": summary,
        "findings": json_findings
    }
    
    with open(filepath, 'w', encoding='utf-8') as f:
        json.dump(output, f, indent=2)
        
    return filepath
