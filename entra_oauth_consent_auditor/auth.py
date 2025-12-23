import sys
import msal
import logging

logger = logging.getLogger(__name__)

def get_graph_token(tenant_id: str, client_id: str, client_secret: str) -> str:
    """
    Acquires a token for Microsoft Graph using Client Credentials flow.
    """
    authority = f"https://login.microsoftonline.com/{tenant_id}"
    app = msal.ConfidentialClientApplication(
        client_id,
        authority=authority,
        client_credential=client_secret
    )

    # The pattern for client credentials flow is to check cache first,
    # but for a CLI one-shot execution, we usually just acquire new.
    # However, MSAL handles cache automatically in memory for the app instance.
    
    result = app.acquire_token_for_client(scopes=["https://graph.microsoft.com/.default"])

    if "access_token" in result:
        logger.info("Successfully acquired Graph API token.")
        return result["access_token"]
    else:
        logger.error(f"Failed to acquire token: {result.get('error')}")
        logger.error(f"Error description: {result.get('error_description')}")
        # Allow the caller to handle the exit, or raise exception
        raise RuntimeError(f"Could not acquire token: {result.get('error_description')}")
