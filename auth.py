import os
from datetime import datetime, timedelta
from jose import JWTError, jwt
from passlib.context import CryptContext
import firebase_admin
from firebase_admin import db
import uuid
import logging

# Set up logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

# Security configurations
SECRET_KEY = os.getenv("JWT_SECRET", "your_strong_secret_key")
ALGORITHM = "HS256"
ACCESS_TOKEN_EXPIRE_MINUTES = 30

# Password hashing context
pwd_context = CryptContext(schemes=["bcrypt"], deprecated="auto")

# Firebase references
def get_users_ref():
    return db.reference('users')

class AuthService:
    def __init__(self):
        self.users_ref = get_users_ref()
    
    def verify_password(self, plain_password: str, hashed_password: str) -> bool:
        """Verify a plain password against a hashed password"""
        return pwd_context.verify(plain_password, hashed_password)
    
    def get_password_hash(self, password: str) -> str:
        """Generate a hashed password from a plain password"""
        return pwd_context.hash(password)
    
    def create_access_token(self, data: dict, expires_delta: timedelta = None) -> str:
        """Create a JWT access token with optional expiration"""
        to_encode = data.copy()
        if expires_delta:
            expire = datetime.utcnow() + expires_delta
        else:
            expire = datetime.utcnow() + timedelta(minutes=15)
        to_encode.update({"exp": expire})
        return jwt.encode(to_encode, SECRET_KEY, algorithm=ALGORITHM)
    
    def decode_token(self, token: str) -> dict:
        """Decode a JWT token and return its payload"""
        try:
            payload = jwt.decode(token, SECRET_KEY, algorithms=[ALGORITHM])
            return payload
        except JWTError as e:
            logger.error(f"Token decoding failed: {e}")
            return None
    
    def get_user_by_email(self, email: str) -> dict:
        """Find a user by email in Firebase"""
        users_snapshot = self.users_ref.get() or {}
        for uid, user_data in users_snapshot.items():
            if user_data.get('email') == email:
                return {"id": uid, **user_data}
        return None
    
    def get_user_by_id(self, user_id: str) -> dict:
        """Find a user by ID in Firebase"""
        user_snapshot = self.users_ref.child(user_id).get()
        if user_snapshot:
            return {"id": user_id, **user_snapshot}
        return None
    
    def authenticate_user(self, email: str, password: str) -> dict:
        """Authenticate a user with email and password"""
        user = self.get_user_by_email(email)
        if not user:
            return None
        if not self.verify_password(password, user['password_hash']):
            return None
        return user
    
    def create_user(self, email: str, password: str, name: str = None) -> dict:
        """Create a new user in Firebase"""
        # Check if email exists
        if self.get_user_by_email(email):
            return None
        
        # Create user
        user_id = str(uuid.uuid4())
        hashed_password = self.get_password_hash(password)
        user_data = {
            "email": email,
            "password_hash": hashed_password,
            "name": name,
            "created_at": datetime.utcnow().isoformat()
        }
        self.users_ref.child(user_id).set(user_data)
        
        return {"id": user_id, **user_data}
    
    def get_current_user(self, token: str) -> dict:
        """Get the current authenticated user from a JWT token"""
        credentials_exception = {
            "status": "error",
            "code": 401,
            "message": "Could not validate credentials"
        }
        
        payload = self.decode_token(token)
        if not payload:
            return None, credentials_exception
        
        email: str = payload.get("sub")
        if not email:
            return None, credentials_exception
        
        user = self.get_user_by_email(email)
        if not user:
            return None, credentials_exception
        
        return user, None
    
    def generate_login_response(self, user: dict) -> dict:
        """Generate login response with access token"""
        access_token_expires = timedelta(minutes=ACCESS_TOKEN_EXPIRE_MINUTES)
        access_token = self.create_access_token(
            data={"sub": user['email']}, 
            expires_delta=access_token_expires
        )
        return {
            "access_token": access_token,
            "token_type": "bearer",
            "user": {
                "id": user['id'],
                "email": user['email'],
                "name": user.get('name')
            }
        }
    
    def change_password(self, user_id: str, current_password: str, new_password: str) -> bool:
        """Change a user's password after verifying current password"""
        user = self.get_user_by_id(user_id)
        if not user:
            return False
        
        if not self.verify_password(current_password, user['password_hash']):
            return False
        
        new_hashed_password = self.get_password_hash(new_password)
        self.users_ref.child(user_id).update({"password_hash": new_hashed_password})
        return True
    
    def reset_password(self, email: str, new_password: str) -> bool:
        """Reset a user's password (without current password verification)"""
        user = self.get_user_by_email(email)
        if not user:
            return False
        
        new_hashed_password = self.get_password_hash(new_password)
        self.users_ref.child(user['id']).update({"password_hash": new_hashed_password})
        return True

# Initialize auth service
auth_service = AuthService()
