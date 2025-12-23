import time
import requests
import logging

logger = logging.getLogger(__name__)

class GraphClient:
    def __init__(self, token: str):
        self.headers = {
            "Authorization": f"Bearer {token}",
            "Content-Type": "application/json"
        }
        self.base_url = "https://graph.microsoft.com/v1.0"

    def get(self, endpoint: str, params=None):
        """
        Executes a single GET request.
        Handles 429 (Too Many Requests) by waiting and retrying.
        """
        url = endpoint if endpoint.startswith("http") else f"{self.base_url}{endpoint}"
        
        while True:
            response = requests.get(url, headers=self.headers, params=params)
            
            if response.status_code == 429:
                retry_after = int(response.headers.get("Retry-After", 5))
                logger.warning(f"Throttled (429). Waiting {retry_after} seconds...")
                time.sleep(retry_after)
                continue
            
            if response.status_code == 403:
                logger.error(f"403 Forbidden accessing {url}. Check permissions.")
                # We raise here because 403 usually means we can't do what we wanted at all.
                # However, for audit, maybe we want to just return None or empty?
                # The user asked for specific error messages on 403.
                # We will let the caller handle the exception or we raise a custom one.
                response.raise_for_status()

            response.raise_for_status()
            return response.json()

    def get_all(self, endpoint: str, params=None):
        """
        Yields all items from a paged collection.
        Automatically follows @odata.nextLink.
        """
        url = endpoint
        current_params = params

        while url:
            data = self.get(url, params=current_params)
            
            # The 'value' key usually holds the list of items
            items = data.get("value", [])
            for item in items:
                yield item
            
            url = data.get("@odata.nextLink")
            # Clear params after first page because nextLink contains them
            current_params = None
