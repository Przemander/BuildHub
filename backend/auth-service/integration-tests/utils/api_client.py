import requests
from typing import Dict, Any, Optional, TypedDict, cast

class ApiResponseData(TypedDict, total=False):
    status: str
    message: str
    data: Dict[str, Any]

class ApiResponse(TypedDict, total=False):
    """API response structure with all fields optional"""
    status_code: int
    data: Optional[ApiResponseData]
    error: str

class AuthApiClient:
    """Klient do komunikacji z API Auth Service"""
    
    def __init__(self, base_url: str):
        self.base_url: str = base_url
        self.auth_token: Optional[str] = None
        self.refresh_token: Optional[str] = None
    
    def register(self, username: str, email: str, password: str) -> ApiResponse:
        """Rejestracja nowego użytkownika"""
        response = requests.post(
            f"{self.base_url}/auth/register",
            json={"username": username, "email": email, "password": password}
        )
        
        result: ApiResponse = {"status_code": response.status_code}
        
        if response.content:
            try:
                data = response.json()
                if data:
                    result["data"] = cast(ApiResponseData, data)
            except:
                pass
                
        return result
    
    def login(self, login: str, password: str) -> ApiResponse:
        """Logowanie za pomocą nazwy użytkownika/emaila i hasła"""
        response = requests.post(
            f"{self.base_url}/auth/login",
            json={"login": login, "password": password}
        )
        
        result: ApiResponse = {"status_code": response.status_code}
        
        if response.content:
            try:
                data = response.json()
                if data:
                    result["data"] = cast(ApiResponseData, data)
                
                if response.status_code == 200 and data and "data" in data:
                    auth_data = data.get("data", {})
                    self.auth_token = auth_data.get("access_token")
                    self.refresh_token = auth_data.get("refresh_token")
            except:
                pass
            
        return result
    
    def refresh(self) -> ApiResponse:
        """Odświeżenie tokenu dostępowego"""
        if not self.refresh_token:
            return {"status_code": 400, "error": "Brak tokenu odświeżania"}
            
        response = requests.post(
            f"{self.base_url}/auth/refresh",
            json={"token": self.refresh_token}
        )
        
        result: ApiResponse = {"status_code": response.status_code}
        
        if response.content:
            try:
                data = response.json()
                if data:
                    result["data"] = cast(ApiResponseData, data)
                
                if response.status_code == 200 and data and "data" in data:
                    auth_data = data.get("data", {})
                    self.auth_token = auth_data.get("access_token")
                    self.refresh_token = auth_data.get("refresh_token")
            except:
                pass
            
        return result
    
    def logout(self) -> ApiResponse:
        """Wylogowanie i unieważnienie tokenu"""
        if not self.auth_token:
            return {"status_code": 400, "error": "Brak tokenu autoryzacyjnego"}
            
        response = requests.post(
            f"{self.base_url}/auth/logout",
            json={"token": self.auth_token}
        )
        
        if response.status_code == 200:
            self.auth_token = None
            self.refresh_token = None
        
        result: ApiResponse = {"status_code": response.status_code}
        
        if response.content:
            try:
                data = response.json()
                if data:
                    result["data"] = cast(ApiResponseData, data)
            except:
                pass
                
        return result
    
    def request_password_reset(self, email: str) -> ApiResponse:
        """Żądanie resetowania hasła"""
        response = requests.post(
            f"{self.base_url}/auth/password-reset/request",
            json={"email": email}
        )
        
        result: ApiResponse = {"status_code": response.status_code}
        
        if response.content:
            try:
                data = response.json()
                if data:
                    result["data"] = cast(ApiResponseData, data)
            except:
                pass
                
        return result
    
    def confirm_password_reset(self, token: str, new_password: str) -> ApiResponse:
        """Potwierdzenie resetowania hasła"""
        response = requests.post(
            f"{self.base_url}/auth/password-reset/confirm",
            json={"token": token, "new_password": new_password}
        )
        
        result: ApiResponse = {"status_code": response.status_code}
        
        if response.content:
            try:
                data = response.json()
                if data:
                    result["data"] = cast(ApiResponseData, data)
            except:
                pass
                
        return result
    
    def authenticated_request(self, method: str, endpoint: str, **kwargs: Any) -> ApiResponse:
        """Wykonanie uwierzytelnionego zapytania do API"""
        if not self.auth_token:
            return {"status_code": 401, "error": "Brak tokenu autoryzacyjnego"}
            
        headers: Dict[str, str] = kwargs.pop("headers", {})
        headers["Authorization"] = f"Bearer {self.auth_token}"
        
        response = requests.request(
            method,
            f"{self.base_url}{endpoint}",
            headers=headers,
            **kwargs
        )
        
        result: ApiResponse = {"status_code": response.status_code}
        
        if response.content:
            try:
                data = response.json()
                if data:
                    result["data"] = cast(ApiResponseData, data)
            except:
                pass
                
        return result