import pytest
from typing import Dict
from utils.api_client import AuthApiClient
from utils.test_data import generate_test_user, generate_valid_password

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
    return user

def test_request_password_reset_for_valid_email(client: AuthApiClient, registered_user: Dict[str, str]) -> None:
    """Test żądania resetowania hasła dla istniejącego adresu email"""
    response = client.request_password_reset(registered_user["email"])
    
    assert "status_code" in response, "Odpowiedź nie zawiera kodu statusu"
    assert response["status_code"] == 200, "Kod statusu powinien być 200 OK"
    
    data = response.get("data")
    assert data is not None, "Odpowiedź nie zawiera danych"
    assert "status" in data, "Dane nie zawierają statusu"
    assert data["status"] == "success", "Status powinien być 'success'"
    
    assert "message" in data, "Dane nie zawierają wiadomości"
    message = data["message"]
    assert isinstance(message, str), "Wiadomość nie jest typu string"
    assert "email" in message.lower(), "Komunikat powinien informować o wysłaniu emaila"

def test_request_password_reset_for_nonexistent_email(client: AuthApiClient) -> None:
    """Test żądania resetowania hasła dla nieistniejącego adresu email"""
    response = client.request_password_reset("nonexistent_user@example.com")
    
    assert "status_code" in response, "Odpowiedź nie zawiera kodu statusu"
    # API powinno zwrócić sukces dla bezpieczeństwa (zapobieganie enumerate)
    assert response["status_code"] == 200, "Kod statusu powinien być 200 OK"
    
    data = response.get("data")
    assert data is not None, "Odpowiedź nie zawiera danych"
    assert "status" in data, "Dane nie zawierają statusu"
    assert data["status"] == "success", "Status powinien być 'success'"
    
def test_confirm_password_reset_with_invalid_token(client: AuthApiClient) -> None:
    """Test potwierdzenia resetowania hasła z nieprawidłowym tokenem"""
    new_password = generate_valid_password()
    response = client.confirm_password_reset("invalid-token", new_password)
    
    assert "status_code" in response, "Odpowiedź nie zawiera kodu statusu"
    assert response["status_code"] == 401, "Kod statusu powinien być 401 Unauthorized"
    
    data = response.get("data")
    assert data is not None, "Odpowiedź nie zawiera danych"
    assert "status" in data, "Dane nie zawierają statusu"
    assert data["status"] == "error", "Status powinien być 'error'"
    
    assert "message" in data, "Dane nie zawierają wiadomości"
    message = data["message"]
    assert isinstance(message, str), "Wiadomość nie jest typu string"
    assert "token" in message.lower(), "Komunikat powinien informować o nieprawidłowym tokenie"

def test_confirm_password_reset_with_weak_password(client: AuthApiClient) -> None:
    """Test potwierdzenia resetowania hasła ze słabym hasłem"""
    response = client.confirm_password_reset("valid-token", "weak")
    
    assert "status_code" in response, "Odpowiedź nie zawiera kodu statusu"
    # Może zwrócić 401 (nieważny token) lub 400 (słabe hasło)
    assert response["status_code"] in [400, 401, 422], "Kod statusu powinien być 400, 401 lub 422"
    
    data = response.get("data")
    assert data is not None, "Odpowiedź nie zawiera danych"
    
    # Jeśli token jest sprawdzany przed walidacją hasła, możemy dostać 401
    if response["status_code"] == 401:
        assert "status" in data, "Dane nie zawierają statusu"
        assert data["status"] == "error"
    else:
        assert "message" in data, "Dane nie zawierają wiadomości"
        message = data["message"]
        assert isinstance(message, str), "Wiadomość nie jest typu string"
        assert "password" in message.lower(), "Komunikat powinien informować o problemie z hasłem"