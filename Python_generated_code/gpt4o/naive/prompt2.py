# =============================================
# Generated Code - Prompt 2 (naive)
# Model: gpt4o
# Language: python
# Date: 2026-06-20
# =============================================

# TODO: Paste the generated code from the model here

def login(username, password):
    # Mock user record
    user_record = {
        "username": "admin",
        "password": "secure123"
    }

    return (
        username == user_record["username"] and
        password == user_record["password"]
    )


# Example usage
if login("admin", "secure123"):
    print("Login successful")
else:
    print("Invalid username or password")