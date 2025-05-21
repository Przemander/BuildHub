import time
import random
import string
from typing import Dict, Literal

def generate_test_user() -> Dict[str, str]:
    """Generuje dane losowego użytkownika do testów"""
    timestamp = int(time.time())
    username = f"testuser_{timestamp}_{random.randint(1000, 9999)}"
    email = f"test_{timestamp}_{random.randint(1000, 9999)}@example.com"
    password = f"Test@{timestamp}_{random.choice(string.ascii_letters)}"
    
    return {
        "username": username,
        "email": email,
        "password": password
    }

def generate_valid_password() -> str:
    """Generuje losowe hasło spełniające wymagania walidacji"""
    # Hasło musi zawierać min. 8 znaków, wielkie i małe litery, cyfry i znak specjalny
    special_chars = "!@#$%^&*()-_=+"
    uppercase = random.choice(string.ascii_uppercase)
    lowercase = random.choice(string.ascii_lowercase)
    digit = random.choice(string.digits)
    special = random.choice(special_chars)
    
    # Reszta znaków losowa
    rest = ''.join(random.choices(
        string.ascii_letters + string.digits + special_chars, 
        k=random.randint(4, 8)
    ))
    
    # Łączymy wszystko i mieszamy
    password = uppercase + lowercase + digit + special + rest
    password_chars = list(password)
    random.shuffle(password_chars)
    
    return ''.join(password_chars)

def generate_invalid_password(case: Literal["too_short", "no_uppercase", "no_lowercase", "no_digit", "no_special", "too_long"] = "too_short") -> str:
    """Generuje nieprawidłowe hasło określonego typu"""
    if case == "too_short":
        return "Aa1!"  # Za krótkie
    elif case == "no_uppercase":
        return "abcdef1!@#"  # Brak wielkich liter
    elif case == "no_lowercase":
        return "ABCDEF1!@#"  # Brak małych liter
    elif case == "no_digit":
        return "abcABC!@#"  # Brak cyfr
    elif case == "no_special":
        return "abcABC123"  # Brak znaków specjalnych
    elif case == "too_long":
        return "Aa1!" * 50  # Za długie
    else:
        return ""  # Puste hasło