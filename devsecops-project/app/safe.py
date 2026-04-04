import hashlib
import os
import re

# File to store user data
USER_DB = "users.txt"

# -----------------------------
# Password Strength Checker
# -----------------------------
def is_strong_password(password):
    if len(password) < 8:
        return False
    if not re.search(r"[A-Z]", password):
        return False
    if not re.search(r"[a-z]", password):
        return False
    if not re.search(r"[0-9]", password):
        return False
    if not re.search(r"[!@#$%^&*(),.?\":{}|<>]", password):
        return False
    return True

# -----------------------------
# Hash Password with Salt
# -----------------------------
def hash_password(password, salt=None):
    if salt is None:
        salt = os.urandom(16)  # generate random salt
    pwd_hash = hashlib.sha256(salt + password.encode()).hexdigest()
    return salt, pwd_hash

# -----------------------------
# Signup Function
# -----------------------------
def signup():
    username = input("Enter username: ")

    password = input("Enter strong password: ")
    if not is_strong_password(password):
        print("❌ Weak password! Try again.")
        return

    salt, pwd_hash = hash_password(password)

    with open(USER_DB, "a") as f:
        f.write(f"{username},{salt.hex()},{pwd_hash}\n")

    print("✅ User registered successfully!")

# -----------------------------
# Login Function
# -----------------------------
def login():
    username = input("Enter username: ")
    password = input("Enter password: ")

    try:
        with open(USER_DB, "r") as f:
            for line in f:
                stored_user, salt_hex, stored_hash = line.strip().split(",")

                if stored_user == username:
                    salt = bytes.fromhex(salt_hex)
                    _, pwd_hash = hash_password(password, salt)

                    if pwd_hash == stored_hash:
                        print("✅ Login successful!")
                        return
                    else:
                        print("❌ Incorrect password")
                        return

        print("❌ User not found")

    except FileNotFoundError:
        print("⚠ No users registered yet.")

# -----------------------------
# Main Menu
# -----------------------------
def main():
    while True:
        print("\n1. Signup")
        print("2. Login")
        print("3. Exit")

        choice = input("Choose option: ")

        if choice == "1":
            signup()
        elif choice == "2":
            login()
        elif choice == "3":
            break
        else:
            print("Invalid choice")

if __name__ == "__main__":
    main()
