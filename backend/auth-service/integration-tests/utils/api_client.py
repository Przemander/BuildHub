import os
import json
import requests
from typing import Dict, Any, Optional, TypedDict

class ApiResponseData(TypedDict, total=False):
    status: str
    message: str
    data: Dict[str, Any]
    user: Dict[str, Any]

class ApiResponse(TypedDict, total=False):
    """API response structure with all fields optional"""
    status_code: int
    data: ApiResponseData
    error: str

class AuthApiClient:
    """Client for communicating with the Auth Service API"""
    
    def __init__(self, base_url: str):
        self.base_url: str = base_url
        # Store tokens as protected attributes
        self._access_token: Optional[str] = None
        self._refresh_token: Optional[str] = None
    
    def register(self, username: str, email: str, password: str) -> ApiResponse:
        """Register a new user"""
        response = requests.post(
            f"{self.base_url}/auth/register",
            json={"username": username, "email": email, "password": password}
        )
        
        result: ApiResponse = {"status_code": response.status_code}
        
        if response.content:
            try:
                result["data"] = response.json()
            except json.JSONDecodeError:
                result["error"] = "Failed to parse response JSON"
                
        return result
    
    def login(self, username_or_email: str, password: str) -> ApiResponse:
        """Login with username/email and password"""
        response = requests.post(
            f"{self.base_url}/auth/login",
            json={"login": username_or_email, "password": password}
        )
        
        result: ApiResponse = {"status_code": response.status_code}
        
        if response.content:
            try:
                result["data"] = response.json()
                if response.status_code == 200 and "data" in result["data"]:
                    # Store tokens if login successful
                    auth_data = result["data"].get("data", {})
                    self._access_token = auth_data.get("access_token")
                    self._refresh_token = auth_data.get("refresh_token")
            except json.JSONDecodeError:
                result["error"] = "Failed to parse response JSON"
            
        return result
    
    def refresh(self) -> ApiResponse:
        """Refresh the access token"""
        if not self._refresh_token:
            return {"status_code": 400, "error": "No refresh token available"}
            
        # Przesyłamy token w ciele żądania
        response = requests.post(
            f"{self.base_url}/auth/refresh",
            json={"token": self._refresh_token}
        )
        
        result: ApiResponse = {"status_code": response.status_code}
        
        if response.content:
            try:
                result["data"] = response.json()
                if response.status_code == 200 and "data" in result["data"]:
                    # Update stored tokens
                    auth_data = result["data"].get("data", {})
                    self._access_token = auth_data.get("access_token")
                    self._refresh_token = auth_data.get("refresh_token")
            except json.JSONDecodeError:
                result["error"] = "Failed to parse response JSON"
        
        return result
    
    def logout(self) -> ApiResponse:
        """Logout the user by invalidating the current access token"""
        # Check if we have an access token
        if not self._access_token:
            return {"status_code": 400, "error": "No access token available"}
        
        # Token musi być przesłany w nagłówku Authorization dla middleware
        headers = {"Authorization": f"Bearer {self._access_token}"}
        
        # Oraz token musi być przesłany w ciele żądania dla handlera
        response = requests.post(
            f"{self.base_url}/auth/logout", 
            headers=headers,
            json={"token": self._access_token} 
        )
        
        result: ApiResponse = {"status_code": response.status_code}
        
        if response.content:
            try:
                result["data"] = response.json()
            except json.JSONDecodeError:
                result["error"] = "Failed to parse response JSON"

        # Clear stored tokens if logout successful
        if response.status_code == 200:
            self._access_token = None
            self._refresh_token = None
            
        return result
    
    @property
    def access_token(self) -> Optional[str]:
        """Get the current access token"""
        return self._access_token
    
    def authenticated_request(self, method: str, endpoint: str, **kwargs: Any) -> ApiResponse:
        """Make an authenticated request to an API endpoint"""
        if not self._access_token:
            return {"status_code": 401, "error": "No access token available"}
            
        headers = kwargs.pop("headers", {})
        headers["Authorization"] = f"Bearer {self._access_token}"
        
        response = requests.request(
            method,
            f"{self.base_url}{endpoint}",
            headers=headers,
            **kwargs
        )
        
        result: ApiResponse = {"status_code": response.status_code}
        
        if response.content:
            try:
                result["data"] = response.json()
            except json.JSONDecodeError:
                result["error"] = "Failed to parse response JSON"
                
        return result
    
    def clean_test_user(self, username: str) -> ApiResponse:
        """Delete a test user from the database"""
        test_secret = self._get_test_secret()
        
        response = requests.post(
            f"{self.base_url}/debug/clean-user",
            json={"username": username, "test_secret": test_secret}
        )
        
        result: ApiResponse = {"status_code": response.status_code}
        
        if response.content:
            try:
                result["data"] = response.json()
            except json.JSONDecodeError:
                result["error"] = "Failed to parse response JSON"
                
        return result

    def reset_rate_limiter(self) -> ApiResponse:
        """Reset the rate limiter for testing"""
        test_secret = self._get_test_secret()
        
        response = requests.post(
            f"{self.base_url}/debug/reset-rate-limiter",
            json={"test_secret": test_secret}
        )
        
        result: ApiResponse = {"status_code": response.status_code}
        
        if response.content:
            try:
                result["data"] = response.json()
            except json.JSONDecodeError:
                result["error"] = "Failed to parse response JSON"
                
        return result

    def activate_account(self, username: str) -> ApiResponse:
        """Activate a user account for testing"""
        test_secret = self._get_test_secret()
        
        response = requests.post(
            f"{self.base_url}/debug/activate-account",
            json={"username": username, "test_secret": test_secret}
        )
        
        result: ApiResponse = {"status_code": response.status_code}
        
        if response.content:
            try:
                result["data"] = response.json()
            except json.JSONDecodeError:
                result["error"] = "Failed to parse response JSON"
                
        return result

    def verify_user_status(self, username: str) -> ApiResponse:
        """Get user status (active/inactive)"""
        test_secret = self._get_test_secret()
        
        response = requests.post(
            f"{self.base_url}/debug/verify-user",
            json={"username": username, "test_secret": test_secret}
        )
        
        result: ApiResponse = {"status_code": response.status_code}
        
        if response.content:
            try:
                result["data"] = response.json()
            except json.JSONDecodeError:
                result["error"] = "Failed to parse response JSON"
                
        return result

    def request_password_reset(self, email: str) -> ApiResponse:
        """Request a password reset for an email address"""
        response = requests.post(
            f"{self.base_url}/auth/password-reset/request",
            json={"email": email}
        )
        
        result: ApiResponse = {"status_code": response.status_code}
        
        if response.content:
            try:
                result["data"] = response.json()
            except json.JSONDecodeError:
                result["error"] = "Failed to parse response JSON"
                
        return result

    def confirm_password_reset(self, token: str, new_password: str) -> ApiResponse:
        """Confirm password reset with token and new password"""
        response = requests.post(
            f"{self.base_url}/auth/password-reset/confirm",
            json={"token": token, "new_password": new_password}
        )
        
        result: ApiResponse = {"status_code": response.status_code}
        
        if response.content:
            try:
                result["data"] = response.json()
            except json.JSONDecodeError:
                result["error"] = "Failed to parse response JSON"
                
        return result

    def create_password_reset_token(self, email: str) -> ApiResponse:
        """Create a password reset token for testing purposes"""
        test_secret = self._get_test_secret()
        
        response = requests.post(
            f"{self.base_url}/debug/create-reset-token",
            json={"email": email, "test_secret": test_secret}
        )
        
        result: ApiResponse = {"status_code": response.status_code}
        
        if response.content:
            try:
                result["data"] = response.json()
            except json.JSONDecodeError:
                result["error"] = "Failed to parse response JSON"
            
        return result

    def _get_test_secret(self) -> str:
        """Get the test secret from environment"""
        return os.environ.get("TEST_SECRET", "your_test_secret_key")