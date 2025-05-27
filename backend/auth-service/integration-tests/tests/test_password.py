import pytest
import time
from typing import Dict, List, Generator, Any
from utils.api_client import AuthApiClient, ApiResponse
from utils.test_data import generate_test_user, generate_valid_password


@pytest.fixture
def registered_user(client: AuthApiClient) -> Dict[str, str]:
    """Creates and registers a test user in the system with an activated account"""
    user = generate_test_user()
    
    # First clean up the user if it exists from previous tests
    client.clean_test_user(user["username"])
    
    # Register user
    response = client.register(
        user["username"],
        user["email"],
        user["password"]
    )
    assert "status_code" in response, "Response does not contain status code"
    assert response["status_code"] == 201, "Failed to register test user"
    
    # Activate account using test endpoint
    activation_response = client.activate_account(user["username"])
    assert "status_code" in activation_response, "Response does not contain status code"
    assert activation_response["status_code"] == 200, "Failed to activate test user"
    
    return user


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
    time.sleep(1)  # Krótkie opóźnienie między testami
    result = client.reset_rate_limiter()
    assert result.get("status_code") == 200, "Failed to reset rate limiter after test"


def test_request_password_reset_for_valid_email(client: AuthApiClient, registered_user: Dict[str, str]) -> None:
    """Test password reset request for existing email address"""
    response = client.request_password_reset(registered_user["email"])
    
    assert "status_code" in response, "Response does not contain status code"
    assert response["status_code"] == 200, "Status code should be 200 OK"
    
    data = response.get("data")
    assert data is not None, "Response does not contain data"
    assert "status" in data, "Data does not contain status"
    assert data["status"] == "success", "Status should be 'success'"
    
    assert "message" in data, "Data does not contain message"
    message = data["message"]
    assert isinstance(message, str), "Message is not a string"
    assert "email" in message.lower(), "Message should indicate email has been sent"


def test_request_password_reset_for_nonexistent_email(client: AuthApiClient) -> None:
    """Test password reset request for non-existent email address"""
    response = client.request_password_reset("nonexistent_user@example.com")
    
    assert "status_code" in response, "Response does not contain status code"
    # API should return success for security (prevent enumeration)
    assert response["status_code"] == 200, "Status code should be 200 OK"
    
    data = response.get("data")
    assert data is not None, "Response does not contain data"
    assert "status" in data, "Data does not contain status"
    assert data["status"] == "success", "Status should be 'success'"
    assert "if the email exists" in data.get("message", "").lower() or "instructions" in data.get("message", "").lower(), "Message should be generic to prevent enumeration"


def test_confirm_password_reset_with_invalid_token(client: AuthApiClient) -> None:
    """Test password reset confirmation with invalid token"""
    new_password = generate_valid_password()
    response = client.confirm_password_reset("invalid-token", new_password)
    
    assert "status_code" in response, "Response does not contain status code"
    assert response["status_code"] == 401, "Status code should be 401 Unauthorized"
    
    data = response.get("data")
    assert data is not None, "Response does not contain data"
    assert "status" in data, "Data does not contain status"
    assert data["status"] in ["error", "unauthorized"], "Status should be 'error' or 'unauthorized'"
    
    assert "message" in data, "Data does not contain message"
    message = data["message"]
    assert isinstance(message, str), "Message is not a string"
    assert any(kw in message.lower() for kw in ["token", "invalid", "expired"]), "Message should indicate token issue"


def test_confirm_password_reset_with_weak_password(client: AuthApiClient) -> None:
    """Test password reset confirmation with weak password"""
    response = client.confirm_password_reset("valid-token", "weak")
    
    assert "status_code" in response, "Response does not contain status code"
    # Most likely will return 401 due to invalid token, but may validate password first in some implementations
    assert response["status_code"] in [400, 401, 422], "Status code should be 400, 401 or 422"
    
    data = response.get("data")
    assert data is not None, "Response does not contain data"
    
    # If token is checked before password validation, we may get 401
    if response["status_code"] == 401:
        assert "status" in data, "Data does not contain status"
        assert data["status"] in ["error", "unauthorized"], "Status should be 'error' or 'unauthorized'"
    else:
        assert "message" in data, "Data does not contain message"
        message = data["message"]
        assert isinstance(message, str), "Message is not a string"
        assert any(kw in message.lower() for kw in ["password", "weak", "requirements"]), "Message should indicate password issue"


def test_full_password_reset_flow(client: AuthApiClient, registered_user: Dict[str, str]) -> None:
    """Test the complete password reset flow from request to confirmation and login"""
    # Use our debug endpoint to directly create a token (bypass email sending)
    token_response = client.create_password_reset_token(registered_user["email"])
    assert "status_code" in token_response, "Response does not contain status code"
    assert token_response.get("status_code") == 200, "Should be able to create reset token"
    
    data = token_response.get("data")
    assert data is not None, "Response should contain data"
    assert "token" in data, "Data should contain token"
    
    reset_token = data["token"]
    assert isinstance(reset_token, str), "Token should be a string"
    assert len(reset_token) > 0, "Token should not be empty"
    
    # Set new password
    new_password = generate_valid_password()
    confirm_response = client.confirm_password_reset(reset_token, new_password)
    
    assert "status_code" in confirm_response, "Response does not contain status code"
    assert confirm_response.get("status_code") == 200, "Password reset confirmation should succeed"
    
    # Verify we can login with the new password
    login_response = client.login(registered_user["username"], new_password)
    assert "status_code" in login_response, "Response does not contain status code"
    assert login_response.get("status_code") == 200, "Should be able to login with the new password"
    
    # Verify login with old password fails
    old_login_response = client.login(registered_user["username"], registered_user["password"])
    assert "status_code" in old_login_response, "Response does not contain status code"
    assert old_login_response.get("status_code") == 401, "Old password should no longer work"


def test_reset_rate_limiting(client: AuthApiClient) -> None:
    """Test that password reset is rate limited"""
    # Attempt multiple password resets for the same email in quick succession
    email = "rate_limit_test@example.com"
    
    # Reset rate limiter first to ensure clean state
    client.reset_rate_limiter()
    
    # The exact number depends on your rate limit configuration
    # Typically 3-5 attempts should trigger rate limiting
    max_attempts = 10
    responses: List[ApiResponse] = []
    
    for _ in range(max_attempts):  # Use underscore for unused loop variable
        response = client.request_password_reset(email)
        responses.append(response)
        
        # If we hit a rate limit, break
        if response.get("status_code") == 429:
            break
    
    # We should have hit a rate limit at some point
    rate_limited = any(r.get("status_code") == 429 for r in responses)
    assert rate_limited, "Password reset requests should be rate limited after multiple attempts"
    
    # Last response should indicate rate limiting
    if responses:  # Check if list is non-empty first
        last_response = responses[-1]
        if last_response.get("status_code") == 429:
            data = last_response.get("data")
            if data is not None:  # Add null check
                assert "status" in data, "Data does not contain status"
                assert data["status"] == "error", "Status should be 'error'"
                
                if "message" in data:  # Add key check
                    message = data["message"]
                    assert any(kw in message.lower() for kw in ["rate", "limit", "try again"]), "Message should indicate rate limiting"