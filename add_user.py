import json, uuid, hashlib

storage_path = "C:/Users/MUTUKU/mu_code/PRJ1/storage.json"

def hash_password(password):
    return hashlib.sha256(password.encode()).hexdigest()

# Load or create file
try:
    with open(storage_path, "r") as f:
        users = json.load(f)
except FileNotFoundError:
    users = {}

# Add user
user_id = str(uuid.uuid4())
users[user_id] = {
    "id": user_id,
    "email": "chrismutuku2005@gmail.com",
    "password": hash_password("Chris#1972")
}

# Save back
with open(storage_path, "w") as f:
    json.dump(users, f, indent=2)

print("✅ User added:", user_id)
