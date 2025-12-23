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
        
        retries = 0
        max_retries = 3
        
        while True:
            try:
                response = requests.get(url, headers=self.headers, params=params)
                
                # Check 429 Throttle
                if response.status_code == 429:
                    retry_after = int(response.headers.get("Retry-After", 5))
                    logger.warning(f"Throttled (429). Waiting {retry_after} seconds...")
                    time.sleep(retry_after)
                    continue
                
                # Check 5xx Server Errors (transient)
                if 500 <= response.status_code < 600:
                    retries += 1
                    if retries <= max_retries:
                        # Exponential backoff or Retry-After
                        retry_after = int(response.headers.get("Retry-After", 2 ** retries))
                        logger.warning(f"Server Error {response.status_code} accessing {url}. Retrying ({retries}/{max_retries}) in {retry_after}s...")
                        time.sleep(retry_after)
                        continue
                    else:
                        logger.error(f"Max retries exceeded for {url}. Last status: {response.status_code}")
                
                if response.status_code == 403:
                    logger.error(f"403 Forbidden accessing {url}. Check permissions.")
                    # Fall through to raise_for_status
                
                response.raise_for_status()
                return response.json()
            except requests.exceptions.RequestException as e:
                # If it's a connection error, maybe we should also retry?
                # For now keeping it simple as per requirements.
                # However, ensure we include URL in error if requests didn't
                # But raise_for_status does include it usually.
                logger.error(f"Request failed for {url}: {e}")
                raise

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
