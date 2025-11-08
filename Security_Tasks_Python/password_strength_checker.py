
import re

def password_strength_checker(password):
    score = 0
    feedback = []
    length_criteria = len(password) >= 8
    uppercase_criteria = bool(re.search(r'[A-Z]', password))
    lowercase_criteria = bool(re.search(r'[a-z]', password))
    number_criteria = bool(re.search(r'[0-9]', password))
    special_char_criteria = bool(re.search(r'[^a-zA-Z0-9\s]', password))

    if length_criteria:
        score += 1; feedback.append("✔️ Password is at least 8 characters long.")
    else: feedback.append("❌ Password should be at least 8 characters long.")
    if uppercase_criteria:
        score += 1; feedback.append("✔️ Contains at least one uppercase letter.")
    else: feedback.append("❌ Add at least one uppercase letter.")
    if lowercase_criteria:
        score += 1; feedback.append("✔️ Contains at least one lowercase letter.")
    else: feedback.append("❌ Add at least one lowercase letter.")
    if number_criteria:
        score += 1; feedback.append("✔️ Contains at least one number.")
    else: feedback.append("❌ Add at least one number.")
    if special_char_criteria:
        score += 1; feedback.append("✔️ Contains at least one special character.")
    else: feedback.append("❌ Add at least one special character.")

    if score == 5: status = "Excellent"
    elif score >= 3: status = "Good"
    elif score >= 1: status = "Weak"
    else: status = "Very Weak"

    return {"score": score, "status": status, "feedback": feedback}

def main():
    print("Welcome to the Password Complexity Checker!")
    while True:
        password = input("Enter a password to check (or 'quit' to exit): ")
        if password.lower() == 'quit':
            break
        results = password_strength_checker(password)
        print(f"Status: {results['status']} (Score: {results['score']}/5)")
        for item in results['feedback']:
            print(item)

if __name__ == "__main__":
    main()
