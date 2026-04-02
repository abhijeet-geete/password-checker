password = input ("Enter a password: ")

if len(password) < 6:
    print("Weak password X (too short)")
elif password.isalpha():
    print("Weak password X (only letters)")
elif password.isdigit():
    print("Weak password X (only numbers)")
else:
    print("Strong password!")