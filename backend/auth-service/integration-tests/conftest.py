import os
import time
import pytest
import requests
from typing import Generator
from utils.api_client import AuthApiClient

# Base URL for the auth service API
BASE_URL = os.environ.get("API_BASE_URL", "http://localhost:3000")

@pytest.fixture(scope="session")
def api_base_url() -> str:
    """Return the base URL for the API"""
    return BASE_URL

@pytest.fixture(scope="session")
def wait_for_api() -> None:
    """Wait for the API to be available before running tests"""
    max_retries = 30
    retry_interval = 1
    
    for attempt in range(max_retries):
        try:
            response = requests.get(f"{BASE_URL}/health")
            if response.status_code == 200:
                print(f"API is available after {attempt+1} attempts")
                return
        except requests.RequestException:
            pass
        
        print(f"Waiting for API to be available... ({attempt+1}/{max_retries})")
        time.sleep(retry_interval)
    
    pytest.fail("API did not become available in time")

@pytest.fixture
def client(api_base_url: str, wait_for_api: None) -> AuthApiClient:
    """Create API client instance for testing"""
    return AuthApiClient(api_base_url)

@pytest.fixture(scope="session", autouse=True)
def cleanup_after_tests(api_base_url: str, wait_for_api: None) -> Generator[None, None, None]:
    """Clean up all test data after tests are complete"""
    yield  # Let the tests run first
    
    # Reset rate limiter after all tests
    client = AuthApiClient(api_base_url)
    client.reset_rate_limiter()