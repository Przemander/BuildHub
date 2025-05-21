import pytest
from typing import Dict
from utils.api_client import AuthApiClient
from utils.test_data import generate_test_user, generate_invalid_password

@pytest.fixture
def test_user() -> Dict[str, str]:
    """Generuje losowe dane testowe użytkownika"""
    return generate_test_user()

def test_register_valid_user(client: AuthApiClient, test_user: Dict[str, str]) -> None:
    """Test rejestracji z prawidłowymi danymi użytkownika"""
    # Wykonanie
    response = client.register(
        test_user["username"],
        test_user["email"],
        test_user["password"]
    )
    
    # Weryfikacja
    assert "status_code" in response, "Odpowiedź nie zawiera kodu statusu"
    assert response["status_code"] == 201, "Kod statusu powinien być 201 Created"
    
    data = response.get("data")
    assert data is not None, "Odpowiedź nie zawiera danych"
    assert "status" in data, "Dane nie zawierają statusu"
    assert data["status"] == "success", "Status powinien być 'success'"
    
    assert "message" in data, "Dane nie zawierają wiadomości"
    message = data["message"]
    assert isinstance(message, str), "Wiadomość nie jest typu string"
    assert "check your email" in message.lower(), "Komunikat powinien informować o weryfikacji email"

def test_register_duplicate_username(client: AuthApiClient, test_user: Dict[str, str]) -> None:
    """Test rejestracji z już istniejącą nazwą użytkownika"""
    # Pierwsza rejestracja
    first_response = client.register(
        test_user["username"],
        test_user["email"],
        test_user["password"]
    )
    assert "status_code" in first_response, "Odpowiedź nie zawiera kodu statusu"
    assert first_response["status_code"] == 201, "Pierwsza rejestracja powinna się udać"
    
    # Próba rejestracji z tą samą nazwą użytkownika, ale innym adresem email
    second_email = test_user["email"].replace("@", "_new@")
    second_response = client.register(
        test_user["username"],
        second_email,
        test_user["password"]
    )
    
    # Weryfikacja
    assert "status_code" in second_response, "Odpowiedź nie zawiera kodu statusu"
    assert second_response["status_code"] == 409, "Kod statusu powinien być 409 Conflict"
    
    data = second_response.get("data")
    assert data is not None, "Odpowiedź nie zawiera danych"
    assert "status" in data, "Dane nie zawierają statusu"
    assert data["status"] == "error", "Status powinien być 'error'"
    
    assert "message" in data, "Dane nie zawierają wiadomości"
    message = data["message"]
    assert isinstance(message, str), "Wiadomość nie jest typu string"
    assert "username" in message.lower(), "Komunikat powinien wskazywać na konflikt nazwy użytkownika"

def test_register_invalid_password(client: AuthApiClient) -> None:
    """Test rejestracji z nieprawidłowym hasłem"""
    user = generate_test_user()
    user["password"] = generate_invalid_password(case="too_short")
    
    # Wykonanie
    response = client.register(
        user["username"],
        user["email"],
        user["password"]
    )
    
    # Weryfikacja
    assert "status_code" in response, "Odpowiedź nie zawiera kodu statusu"
    assert response["status_code"] in [400, 422], "Kod statusu powinien być 400 Bad Request lub 422 Unprocessable Entity"
    
    data = response.get("data")
    assert data is not None, "Odpowiedź nie zawiera danych"
    assert "status" in data, "Dane nie zawierają statusu"
    assert data["status"] == "error", "Status powinien być 'error'"
    
    assert "message" in data, "Dane nie zawierają wiadomości"
    message = data["message"]
    assert isinstance(message, str), "Wiadomość nie jest typu string"
    assert "password" in message.lower(), "Komunikat powinien wskazywać na problem z hasłem"