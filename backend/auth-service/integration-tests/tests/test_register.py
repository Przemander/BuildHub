import time
import pytest
from typing import Dict, Generator, Any
from utils.api_client import AuthApiClient
from utils.test_data import generate_test_user, generate_invalid_password

@pytest.fixture
def test_user() -> Dict[str, str]:
    """Generates random test user data"""
    return generate_test_user()


@pytest.fixture(scope="function", autouse=True)
def reset_rate_limits(client: AuthApiClient) -> Generator[None, Any, None]:
    """Reset rate limits before and after each test"""
    # Reset przed testem
    result = client.reset_rate_limiter()
    assert result.get("status_code") == 200, "Failed to reset rate limiter before test"
    time.sleep(1)  # Krótka pauza po resecie
    
    # Wykonaj test
    yield
    
    # Reset po teście
    time.sleep(1)  # Krótka pauza przed resetem
    result = client.reset_rate_limiter()
    assert result.get("status_code") == 200, "Failed to reset rate limiter after test"


def test_register_valid_user(client: AuthApiClient, test_user: Dict[str, str]) -> None:
    """Test registration with valid user data"""
    # Execution
    response = client.register(
        test_user["username"],
        test_user["email"],
        test_user["password"]
    )
    
    # Verification
    assert "status_code" in response, "Response does not contain status code"
    assert response["status_code"] == 201, "Status code should be 201 Created"
    
    data = response.get("data")
    assert data is not None, "Response does not contain data"
    assert "status" in data, "Data does not contain status"
    assert data["status"] == "success", "Status should be 'success'"
    
    assert "message" in data, "Data does not contain message"
    message = data["message"]
    assert isinstance(message, str), "Message is not a string"
    assert "check your email" in message.lower(), "Message should indicate email verification"


def test_register_duplicate_username(client: AuthApiClient, test_user: Dict[str, str]) -> None:
    """Test registration with an existing username"""
    # First registration
    first_response = client.register(
        test_user["username"],
        test_user["email"],
        test_user["password"]
    )
    assert "status_code" in first_response, "Response does not contain status code"
    assert first_response["status_code"] == 201, "First registration should succeed"
    
    # Reset rate limits między żądaniami
    client.reset_rate_limiter()
    time.sleep(1)
    
    # Attempt to register with the same username but different email
    second_email = test_user["email"].replace("@", "_new@")
    second_response = client.register(
        test_user["username"],
        second_email,
        test_user["password"]
    )
    
    # Verification
    assert "status_code" in second_response, "Response does not contain status code"
    assert second_response["status_code"] == 409, "Status code should be 409 Conflict"
    
    data = second_response.get("data")
    assert data is not None, "Response does not contain data"
    assert "status" in data, "Data does not contain status"
    assert data["status"] == "error", "Status should be 'error'"
    
    assert "message" in data, "Data does not contain message"
    message = data["message"]
    assert isinstance(message, str), "Message is not a string"
    assert "username" in message.lower(), "Message should indicate username conflict"


def test_register_duplicate_email(client: AuthApiClient, test_user: Dict[str, str]) -> None:
    """Test registration with an existing email address"""
    # First registration
    first_response = client.register(
        test_user["username"],
        test_user["email"],
        test_user["password"]
    )
    assert "status_code" in first_response, "Response does not contain status code"
    assert first_response["status_code"] == 201, "First registration should succeed"
    
    # Attempt to register with the same email but different username
    second_username = f"new_{test_user['username']}"
    second_response = client.register(
        second_username,
        test_user["email"],
        test_user["password"]
    )
    
    # Verification
    assert "status_code" in second_response, "Response does not contain status code"
    assert second_response["status_code"] == 409, "Status code should be 409 Conflict"
    
    data = second_response.get("data")
    assert data is not None, "Response does not contain data"
    assert "status" in data, "Data does not contain status"
    assert data["status"] == "error", "Status should be 'error'"
    
    assert "message" in data, "Data does not contain message"
    message = data["message"]
    assert isinstance(message, str), "Message is not a string"
    assert "email" in message.lower(), "Message should indicate email conflict"


def test_register_invalid_password(client: AuthApiClient) -> None:
    """Test registration with invalid password"""
    user = generate_test_user()
    user["password"] = generate_invalid_password(case="too_short")
    
    # Execution
    response = client.register(
        user["username"],
        user["email"],
        user["password"]
    )
    
    # Verification
    assert "status_code" in response, "Response does not contain status code"
    assert response["status_code"] in [400, 422], "Status code should be 400 Bad Request or 422 Unprocessable Entity"
    
    data = response.get("data")
    assert data is not None, "Response does not contain data"
    assert "status" in data, "Data does not contain status"
    assert data["status"] == "error", "Status should be 'error'"
    
    assert "message" in data, "Data does not contain message"
    message = data["message"]
    assert isinstance(message, str), "Message is not a string"
    assert "password" in message.lower(), "Message should indicate password problem"


def test_register_invalid_email_format(client: AuthApiClient) -> None:
    """Test registration with invalid email format"""
    user = generate_test_user()
    user["email"] = "invalid-email"
    
    # Execution
    response = client.register(
        user["username"],
        user["email"],
        user["password"]
    )
    
    # Verification
    assert "status_code" in response, "Response does not contain status code"
    assert response["status_code"] == 400, "Status code should be 400 Bad Request"
    
    data = response.get("data")
    assert data is not None, "Response does not contain data"
    assert "status" in data, "Data does not contain status"
    assert data["status"] == "error", "Status should be 'error'"
    
    assert "message" in data, "Data does not contain message"
    message = data["message"]
    assert isinstance(message, str), "Message is not a string"
    assert "email" in message.lower(), "Message should indicate email format problem"


def test_register_invalid_username(client: AuthApiClient) -> None:
    """Test registration with invalid username"""
    user = generate_test_user()
    user["username"] = ""  # or very_short
    
    # Execution
    response = client.register(
        user["username"],
        user["email"],
        user["password"]
    )
    
    # Verification
    assert "status_code" in response, "Response does not contain status code"
    assert response["status_code"] == 400, "Status code should be 400 Bad Request"
    
    data = response.get("data")
    assert data is not None, "Response does not contain data"
    assert "status" in data, "Data does not contain status"
    assert data["status"] == "error", "Status should be 'error'"
    
    assert "message" in data, "Data does not contain message"
    message = data["message"]
    assert isinstance(message, str), "Message is not a string"
    assert "username" in message.lower(), "Message should indicate username problem"