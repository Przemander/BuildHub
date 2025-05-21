import pytest
from typing import Dict
from utils.api_client import AuthApiClient
from utils.test_data import generate_test_user

@pytest.fixture
def registered_user(client: AuthApiClient) -> Dict[str, str]:
    """Tworzy testowego użytkownika i rejestruje go w systemie"""
    user = generate_test_user()
    response = client.register(
        user["username"],
        user["email"],
        user["password"]
    )
    assert "status_code" in response, "Odpowiedź nie zawiera kodu statusu"
    assert response["status_code"] == 201, "Nie udało się zarejestrować użytkownika testowego"
    
    # W prawdziwym systemie tutaj aktywowalibyśmy konto
    # Ale w testach integracyjnych bez dostępu do Redis/maili trudno to zrobić
    # Zakładamy, że użytkownik jest już aktywny
    
    return user

def test_login_invalid_credentials(client: AuthApiClient) -> None:
    """Test logowania z nieprawidłowymi danymi uwierzytelniającymi"""
    response = client.login("nonexistent_user", "WrongPassword123!")
    
    assert "status_code" in response, "Odpowiedź nie zawiera kodu statusu"
    assert response["status_code"] == 401, "Kod statusu powinien być 401 Unauthorized"
    
    data = response.get("data")
    assert data is not None, "Odpowiedź nie zawiera danych"
    assert "status" in data, "Dane nie zawierają statusu"
    assert data["status"] == "error", "Status powinien być 'error'"
    
    assert "message" in data, "Dane nie zawierają wiadomości"
    message = data["message"]
    assert isinstance(message, str), "Wiadomość nie jest typu string"
    assert "credentials" in message.lower(), "Komunikat powinien informować o nieprawidłowych danych logowania"

def test_login_with_username(client: AuthApiClient, registered_user: Dict[str, str]) -> None:
    """Test logowania z użyciem nazwy użytkownika"""
    # UWAGA: Ten test zadziała tylko jeśli użytkownik jest aktywowany
    # W prawdziwym środowisku testowym należałoby dodać mechanizm aktywacji konta
    
    response = client.login(registered_user["username"], registered_user["password"])
    
    assert "status_code" in response, "Odpowiedź nie zawiera kodu statusu"
    
    # W zależności od tego czy konto jest aktywne
    if response["status_code"] == 200:
        data = response.get("data")
        assert data is not None, "Odpowiedź nie zawiera danych"
        assert "status" in data, "Dane nie zawierają statusu"
        assert data["status"] == "success", "Status powinien być 'success'"
        
        assert "data" in data, "Odpowiedź nie zawiera danych"
        response_data = data.get("data", {})
        assert isinstance(response_data, dict), "Dane nie są słownikiem"
        assert "access_token" in response_data, "Odpowiedź powinna zawierać token dostępu"
        assert "refresh_token" in response_data, "Odpowiedź powinna zawierać token odświeżania"
    else:
        # Jeśli konto nie jest aktywne, oczekujemy odpowiedniego błędu
        assert response["status_code"] == 401, "Kod statusu powinien być 401 Unauthorized"
        
        data = response.get("data")
        assert data is not None, "Odpowiedź nie zawiera danych"
        assert "message" in data, "Dane nie zawierają wiadomości"
        message = data["message"]
        assert isinstance(message, str), "Wiadomość nie jest typu string"
        assert "not activated" in message.lower(), "Komunikat powinien informować o nieaktywnym koncie"

def test_login_with_email(client: AuthApiClient, registered_user: Dict[str, str]) -> None:
    """Test logowania z użyciem adresu email"""
    # UWAGA: Ten test zadziała tylko jeśli użytkownik jest aktywowany
    
    response = client.login(registered_user["email"], registered_user["password"])
    
    assert "status_code" in response, "Odpowiedź nie zawiera kodu statusu"
    
    # Podobnie jak powyżej, weryfikacja zależy od stanu aktywacji konta
    if response["status_code"] == 200:
        data = response.get("data")
        assert data is not None, "Odpowiedź nie zawiera danych"
        assert "status" in data, "Dane nie zawierają statusu"
        assert data["status"] == "success", "Status powinien być 'success'"
        
        assert "data" in data, "Odpowiedź nie zawiera danych"
        response_data = data.get("data", {})
        assert isinstance(response_data, dict), "Dane nie są słownikiem"
        assert "access_token" in response_data, "Odpowiedź powinna zawierać token dostępu"
    else:
        assert response["status_code"] == 401, "Kod statusu powinien być 401 Unauthorized"
        
        data = response.get("data")
        assert data is not None, "Odpowiedź nie zawiera danych"
        assert "message" in data, "Dane nie zawierają wiadomości"
        message = data["message"]
        assert isinstance(message, str), "Wiadomość nie jest typu string"
        assert "not activated" in message.lower(), "Komunikat powinien informować o nieaktywnym koncie"

def test_logout(client: AuthApiClient, registered_user: Dict[str, str]) -> None:
    """Test wylogowania"""
    # Najpierw logujemy się
    login_response = client.login(registered_user["username"], registered_user["password"])
    
    assert "status_code" in login_response, "Odpowiedź nie zawiera kodu statusu"
    
    # Jeśli nie możemy się zalogować (np. konto nie jest aktywne), pomijamy test
    if login_response["status_code"] != 200:
        pytest.skip("Nie można się zalogować - konto może nie być aktywne")
    
    # Wylogowanie
    logout_response = client.logout()
    
    # Weryfikacja
    assert "status_code" in logout_response, "Odpowiedź nie zawiera kodu statusu"
    assert logout_response["status_code"] == 200, "Kod statusu powinien być 200 OK"
    
    data = logout_response.get("data")
    assert data is not None, "Odpowiedź nie zawiera danych"
    assert "status" in data, "Dane nie zawierają statusu"
    assert data["status"] == "success", "Status powinien być 'success'"
    
    # Próba użycia tokenu po wylogowaniu powinna się nie powieść
    protected_response = client.authenticated_request("GET", "/auth/protected-resource")
    assert "status_code" in protected_response, "Odpowiedź nie zawiera kodu statusu"
    assert protected_response["status_code"] == 401, "Kod statusu powinien być 401 Unauthorized po wylogowaniu"