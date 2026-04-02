import re
from dataclasses import dataclass, field
from typing import List


COMMON_WEAK_PASSWORDS = {
    "password",
    "password123",
    "123456",
    "12345678",
    "qwerty",
    "abc123",
    "admin",
    "letmein",
    "welcome",
    "iloveyou",
}


@dataclass
class PasswordReport:
    password: str
    score: int = 0
    max_score: int = 8
    strength: str = "Very Weak"
    checks_passed: List[str] = field(default_factory=list)
    issues: List[str] = field(default_factory=list)
    suggestions: List[str] = field(default_factory=list)


def contains_uppercase(password: str) -> bool:
    return any(char.isupper() for char in password)


def contains_lowercase(password: str) -> bool:
    return any(char.islower() for char in password)


def contains_digit(password: str) -> bool:
    return any(char.isdigit() for char in password)


def contains_symbol(password: str) -> bool:
    return bool(re.search(r"[^A-Za-z0-9]", password))


def has_repeated_chars(password: str) -> bool:
    return bool(re.search(r"(.)\1{2,}", password))


def has_sequential_pattern(password: str) -> bool:
    sequences = [
        "1234",
        "2345",
        "3456",
        "4567",
        "5678",
        "6789",
        "abcd",
        "bcde",
        "cdef",
        "defg",
        "qwer",
        "asdf",
        "zxcv",
    ]
    lowered = password.lower()
    return any(seq in lowered for seq in sequences)


def evaluate_password(password: str) -> PasswordReport:
    report = PasswordReport(password=password)

    if not password:
        report.issues.append("Password is empty.")
        report.suggestions.append("Enter a password to evaluate.")
        return report

    length = len(password)

    if length >= 12:
        report.score += 2
        report.checks_passed.append("Length is at least 12 characters.")
    elif length >= 8:
        report.score += 1
        report.checks_passed.append("Length is at least 8 characters.")
    else:
        report.issues.append("Password is shorter than 8 characters.")
        report.suggestions.append("Use at least 12 characters for stronger security.")

    if contains_uppercase(password):
        report.score += 1
        report.checks_passed.append("Contains uppercase letters.")
    else:
        report.issues.append("No uppercase letters found.")
        report.suggestions.append("Add at least one uppercase letter.")

    if contains_lowercase(password):
        report.score += 1
        report.checks_passed.append("Contains lowercase letters.")
    else:
        report.issues.append("No lowercase letters found.")
        report.suggestions.append("Add at least one lowercase letter.")

    if contains_digit(password):
        report.score += 1
        report.checks_passed.append("Contains digits.")
    else:
        report.issues.append("No digits found.")
        report.suggestions.append("Add at least one number.")

    if contains_symbol(password):
        report.score += 1
        report.checks_passed.append("Contains symbols.")
    else:
        report.issues.append("No symbols found.")
        report.suggestions.append("Add at least one special character, like ! or @.")

    lowered = password.lower()
    if lowered in COMMON_WEAK_PASSWORDS:
        report.issues.append("Password matches a very common weak password.")
        report.suggestions.append("Avoid common passwords and use a unique passphrase.")
    else:
        report.score += 1
        report.checks_passed.append("Not found in a small list of common weak passwords.")

    if has_repeated_chars(password):
        report.issues.append("Contains repeated characters pattern (example: aaa or 111).")
        report.suggestions.append("Avoid repeated character sequences.")
    else:
        report.score += 1
        report.checks_passed.append("No obvious repeated character pattern detected.")

    if has_sequential_pattern(password):
        report.issues.append("Contains predictable sequential pattern.")
        report.suggestions.append("Avoid sequences like 1234, abcd, or qwer.")
    else:
        report.score += 1
        report.checks_passed.append("No obvious sequential pattern detected.")

    if report.score <= 2:
        report.strength = "Very Weak"
    elif report.score <= 4:
        report.strength = "Weak"
    elif report.score <= 6:
        report.strength = "Moderate"
    elif report.score == 7:
        report.strength = "Strong"
    else:
        report.strength = "Very Strong"

    return report


def print_report(report: PasswordReport) -> None:
    print("\n--- Password Audit Report ---")
    print(f"Password length: {len(report.password)}")
    print(f"Score: {report.score}/{report.max_score}")
    print(f"Strength: {report.strength}")

    print("\nChecks passed:")
    if report.checks_passed:
        for item in report.checks_passed:
            print(f"  - {item}")
    else:
        print("  - None")

    print("\nIssues found:")
    if report.issues:
        for item in report.issues:
            print(f"  - {item}")
    else:
        print("  - No major issues detected.")

    print("\nSuggestions:")
    if report.suggestions:
        seen = set()
        for item in report.suggestions:
            if item not in seen:
                print(f"  - {item}")
                seen.add(item)
    else:
        print("  - No suggestions. Password looks strong.")

    print("-----------------------------\n")


def main() -> None:
    print("Password Checker / Password Audit Tool")
    print("Type 'exit' to quit.\n")

    while True:
        password = input("Enter a password to evaluate: ").strip()

        if password.lower() == "exit":
            print("Goodbye.")
            break

        report = evaluate_password(password)
        print_report(report)


if __name__ == "__main__":
    main()
