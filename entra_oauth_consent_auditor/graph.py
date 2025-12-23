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
        Executes a single GET request with retries and timeouts.
        Handles 429 (Too Many Requests) and 5xx Server Errors with finite retries.
        """
        url = endpoint if endpoint.startswith("http") else f"{self.base_url}{endpoint}"
        
        # Timeout: (connect, read)
        # 3.05 for connect (slightly > 3s standard TCP timeout)
        # 30 for read (Graph can be slow)
        timeout = (3.05, 30)
        
        retries_429 = 0
        max_retries_429 = 5  # Cap 429 retries
        
        retries_server = 0
        max_retries_server = 3 # Cap 5xx/transient retries
        
        while True:
            try:
                response = requests.get(url, headers=self.headers, params=params, timeout=timeout)
                
                # Check 429 Throttle
                if response.status_code == 429:
                    retries_429 += 1
                    if retries_429 <= max_retries_429:
                        retry_after = int(response.headers.get("Retry-After", 5))
                        # Cap max wait to avoiding hang if server says "Retry-After: 9999"
                        retry_after = min(retry_after, 60) 
                        logger.warning(f"Throttled 429 on {url}. Waiting {retry_after}s (Retry {retries_429}/{max_retries_429})...")
                        time.sleep(retry_after)
                        continue
                    else:
                        raise RuntimeError(f"Max 429 retries exceeded for {url}.")

                # Check 5xx Server Errors (transient)
                if 500 <= response.status_code < 600:
                    retries_server += 1
                    if retries_server <= max_retries_server:
                        # Exponential backoff
                        retry_after = int(response.headers.get("Retry-After", 2 ** retries_server))
                        logger.warning(f"Server Error {response.status_code} on {url}. Retrying ({retries_server}/{max_retries_server}) in {retry_after}s...")
                        time.sleep(retry_after)
                        continue
                    else:
                        # Raise explicit error after max retries
                        logger.error(f"Max server retries exceeded for {url}. Status: {response.status_code}")
                        response.raise_for_status() # Will raise HTTPError
                
                if response.status_code == 403:
                    logger.error(f"403 Forbidden accessing {url}. Check permissions.")
                    # Fall through to raise_for_status to bubble up exception
                
                response.raise_for_status()
                return response.json()
            
            except requests.exceptions.RequestException as e:
                # Handle transient network errors (timeouts, connection errors)
                # But NOT 4xx/5xx responses which are covered above (except if raise_for_status called)
                # If it's a timeout or connection error, we can retry using server retry budget
                if isinstance(e, (requests.exceptions.Timeout, requests.exceptions.ConnectionError)):
                    retries_server += 1
                    if retries_server <= max_retries_server:
                        wait = 2 ** retries_server
                        logger.warning(f"Transient error {type(e).__name__} on {url}: {e}. Retrying ({retries_server}/{max_retries_server}) in {wait}s...")
                        time.sleep(wait)
                        continue
                
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
