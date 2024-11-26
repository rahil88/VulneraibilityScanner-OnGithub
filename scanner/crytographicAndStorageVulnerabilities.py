import requests
import random
import hashlib
import argparse

def check_insecure_cookie_flags(target_url):
    """
    Checks if cookies on the target URL have insecure flags (Secure, HttpOnly, SameSite).
    
    Args:
        target_url (str): The target URL to test for insecure cookie flags.
        
    Returns:
        bool: True if insecure cookie flags are detected, False otherwise.
    """
    try:
        response = requests.get(target_url, timeout=10)
        cookies = response.cookies

        for cookie in cookies:
            if not cookie.secure or not cookie.has_nonstandard_attr('HttpOnly') or not cookie.has_nonstandard_attr('SameSite'):
                print(f"[Cookies] Insecure cookie found: {cookie.name}")
                return True  # Vulnerable cookie found
        print("[Cookies] All cookies are secure.")
        return False  # All cookies are secure
    except requests.RequestException as e:
        print(f"[Cookies] Error while checking cookies: {e}")
        return False  # Unable to test

def check_poor_random_number():
    """
    Simulates a scenario where a poor random number generator (RNG) is used.
    
    Returns:
        bool: True if a hardcoded seed is detected, False otherwise.
    """
    try:
        seed = random.seed(12345)  # Example of a hardcoded seed
        if seed is not None:
            print("[RNG] Poor random number generator detected (predictable seed).")
            return True  # Vulnerable due to predictable RNG
        return False  # RNG is secure
    except Exception as e:
        print(f"[RNG] Error while checking RNG: {e}")
        return False

def check_weak_hashing(password):
    """
    Checks if weak hashing algorithms (MD5, SHA1) are used.
    
    Args:
        password (str): The password to hash using weak algorithms.
        
    Returns:
        bool: True if weak algorithms are detected, False otherwise.
    """
    weak_algorithms = [hashlib.md5, hashlib.sha1]
    try:
        for algo in weak_algorithms:
            hashed = algo(password.encode()).hexdigest()
            print(f"[Hashing] Weak hash generated using {algo.__name__}: {hashed}")
            return True  # Vulnerable due to weak algorithm
        print("[Hashing] No weak hashing algorithms detected.")
        return False  # Secure hashing
    except Exception as e:
        print(f"[Hashing] Error while checking hashing: {e}")
        return False

