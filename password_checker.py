import re
import math

# Common weak passwords (basic blacklist used in real security tools)
COMMON_PASSWORDS = {
    "password", "123456", "123456789", "qwerty", "letmein",
    "admin", "welcome", "password123", "iloveyou"
}

def estimate_crack_time(password):
    """Rough estimate of brute force cracking time."""
    charset_size = 0

    if re.search(r"[a-z]", password):
        charset_size += 26
    if re.search(r"[A-Z]", password):
        charset_size += 26
    if re.search(r"\d", password):
        charset_size += 10
    if re.search(r"[!@#$%^&*(),.?\":{}|<>]", password):
        charset_size += 20

    if charset_size == 0:
        return "Instant"

    # assume 1 billion guesses per second (very rough modern estimate)
    combinations = charset_size ** len(password)
    seconds = combinations / 1e9

    if seconds < 1:
        return "Instant"
    elif seconds < 60:
        return "Seconds"
    elif seconds < 3600:
        return "Minutes"
    elif seconds < 86400:
        return "Hours"
    elif seconds < 31536000:
        return "Days"
    else:
        return "Years"

def check_password(password):
    score = 0
    feedback = []

    # Blacklist check
    if password.lower() in COMMON_PASSWORDS:
        feedback.append("Password is too common and easily guessable.")
        score -= 1

    # Length check
    if len(password) >= 12:
        score += 1
    else:
        feedback.append("Use at least 12 characters.")

    # Uppercase
    if re.search(r"[A-Z]", password):
        score += 1
    else:
        feedback.append("Add an uppercase letter.")

    # Lowercase
    if re.search(r"[a-z]", password):
        score += 1
    else:
        feedback.append("Add a lowercase letter.")

    # Numbers
    if re.search(r"\d", password):
        score += 1
    else:
        feedback.append("Add a number.")

    # Special characters
    if re.search(r"[!@#$%^&*(),.?\":{}|<>]", password):
        score += 1
    else:
        feedback.append("Add a special character.")

    # Rating system
    if score <= 1:
        rating = "Very Weak"
    elif score == 2:
        rating = "Weak"
    elif score == 3:
        rating = "Fair"
    elif score == 4:
        rating = "Good"
    else:
        rating = "Strong"

    return rating, feedback


# Run program
print("\n=== PASSWORD SECURITY ANALYZER ===\n")

password = input("Enter a password: ")

rating, feedback = check_password(password)
crack_time = estimate_crack_time(password)

print("\n--- RESULTS ---")
print("Password Rating:", rating)
print("Estimated Crack Time:", crack_time)

print("\n--- SECURITY FEEDBACK ---")
if feedback:
    for item in feedback:
        print("-", item)
else:
    print("Your password meets all recommended security standards.")

print("\n=============================\n")