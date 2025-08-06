from fastapi import FastAPI, Depends, HTTPException, status, UploadFile, File
from fastapi.security import OAuth2PasswordBearer, OAuth2PasswordRequestForm
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel
from datetime import datetime, timedelta
from jose import JWTError, jwt
from passlib.context import CryptContext
import uuid
import os
import cloudinary
import cloudinary.uploader
import firebase_admin
from firebase_admin import credentials, db
import json
import logging

# Initialize Firebase
cred = credentials.Certificate("serviceAccountKey.json")  # Download from Firebase console
firebase_admin.initialize_app(cred, {
    'databaseURL': 'https://expense-tracker-1ac93-default-rtdb.firebaseio.com/'
})

# Initialize FastAPI app
app = FastAPI()

# CORS Configuration
app.add_middleware(
    CORSMiddleware,
    allow_origins=["https://christopherjohn1972.github.io"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# Security configurations
SECRET_KEY = os.getenv("JWT_SECRET", "your_strong_secret_key")
ALGORITHM = "HS256"
ACCESS_TOKEN_EXPIRE_MINUTES = 30

pwd_context = CryptContext(schemes=["bcrypt"], deprecated="auto")
oauth2_scheme = OAuth2PasswordBearer(tokenUrl="token")

# Cloudinary Configuration
CLOUDINARY_CLOUD_NAME = "dszqqytxo"
CLOUDINARY_API_KEY = "648612798572317"
CLOUDINARY_API_SECRET = os.getenv("CLOUDINARY_API_SECRET", "your_api_secret")

# Configure Cloudinary
cloudinary.config(
    cloud_name=CLOUDINARY_CLOUD_NAME,
    api_key=CLOUDINARY_API_KEY,
    api_secret=CLOUDINARY_API_SECRET
)

# Set up logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

# Firebase Database References
users_ref = db.reference('users')
expenses_ref = db.reference('expenses')
wallets_ref = db.reference('wallets')
receipts_ref = db.reference('receipts')

# Pydantic models
class UserCreate(BaseModel):
    email: str
    password: str
    name: str = None

class UserResponse(BaseModel):
    id: str
    email: str
    name: str

class Token(BaseModel):
    access_token: str
    token_type: str

class TokenData(BaseModel):
    email: str = None

class ExpenseCreate(BaseModel):
    amount: float
    category: str
    description: str = None
    wallet_id: str = None
    date: str = None

class ExpenseResponse(BaseModel):
    id: str
    amount: float
    category: str
    description: str
    date: str
    user_id: str
    wallet_id: str = None

class WalletCreate(BaseModel):
    name: str

class WalletResponse(BaseModel):
    id: str
    name: str
    created_by: str

class ReceiptCreate(BaseModel):
    expense_id: str
    cloudinary_url: str
    ocr_text: str
    confidence: float
    parsed_data: dict

# Auth helper functions
def verify_password(plain_password, hashed_password):
    return pwd_context.verify(plain_password, hashed_password)

def get_password_hash(password):
    return pwd_context.hash(password)

def create_access_token(data: dict, expires_delta: timedelta = None):
    to_encode = data.copy()
    if expires_delta:
        expire = datetime.utcnow() + expires_delta
    else:
        expire = datetime.utcnow() + timedelta(minutes=15)
    to_encode.update({"exp": expire})
    encoded_jwt = jwt.encode(to_encode, SECRET_KEY, algorithm=ALGORITHM)
    return encoded_jwt

def get_current_user(token: str = Depends(oauth2_scheme)):
    credentials_exception = HTTPException(
        status_code=status.HTTP_401_UNAUTHORIZED,
        detail="Could not validate credentials",
        headers={"WWW-Authenticate": "Bearer"},
    )
    try:
        payload = jwt.decode(token, SECRET_KEY, algorithms=[ALGORITHM])
        email: str = payload.get("sub")
        if email is None:
            raise credentials_exception
        token_data = TokenData(email=email)
    except JWTError:
        raise credentials_exception

    # Find user in Firebase
    users = users_ref.get()
    if not users:
        raise credentials_exception

    user = None
    for uid, user_data in users.items():
        if user_data.get('email') == email:
            user = {"id": uid, **user_data}
            break

    if user is None:
        raise credentials_exception
    return user

# Routes
@app.post("/register", response_model=UserResponse)
def register(user: UserCreate):
    # Check if email exists
    users = users_ref.get() or {}
    for uid, user_data in users.items():
        if user_data.get('email') == user.email:
            raise HTTPException(status_code=400, detail="Email already registered")

    # Create user
    user_id = str(uuid.uuid4())
    hashed_password = get_password_hash(user.password)
    user_data = {
        "email": user.email,
        "password_hash": hashed_password,
        "name": user.name,
        "created_at": datetime.utcnow().isoformat()
    }
    users_ref.child(user_id).set(user_data)

    return {"id": user_id, "email": user.email, "name": user.name}

@app.post("/token", response_model=Token)
def login_for_access_token(form_data: OAuth2PasswordRequestForm = Depends()):
    # Find user by email
    users = users_ref.get() or {}
    user = None
    for uid, user_data in users.items():
        if user_data.get('email') == form_data.username:
            user = {"id": uid, **user_data}
            break

    if not user or not verify_password(form_data.password, user['password_hash']):
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Incorrect email or password",
            headers={"WWW-Authenticate": "Bearer"},
        )

    access_token_expires = timedelta(minutes=ACCESS_TOKEN_EXPIRE_MINUTES)
    access_token = create_access_token(
        data={"sub": user['email']}, expires_delta=access_token_expires
    )
    return {"access_token": access_token, "token_type": "bearer"}

@app.post("/expenses", response_model=ExpenseResponse)
def create_expense(
    expense: ExpenseCreate,
    current_user: dict = Depends(get_current_user)
):
    # Set default date to now if not provided
    if not expense.date:
        expense.date = datetime.utcnow().isoformat()

    # Check wallet membership if provided
    if expense.wallet_id:
        wallet = wallets_ref.child(expense.wallet_id).get()
        if not wallet:
            raise HTTPException(status_code=404, detail="Wallet not found")

        wallet_members = wallets_ref.child(f"{expense.wallet_id}/members").get() or {}
        if current_user['id'] not in wallet_members:
            raise HTTPException(status_code=403, detail="Not a wallet member")

    # Create expense
    expense_id = str(uuid.uuid4())
    expense_data = {
        "user_id": current_user['id'],
        "wallet_id": expense.wallet_id,
        "amount": expense.amount,
        "category": expense.category,
        "description": expense.description,
        "date": expense.date
    }
    expenses_ref.child(expense_id).set(expense_data)

    return {"id": expense_id, **expense_data}

@app.get("/expenses", response_model=list[ExpenseResponse])
def get_expenses(current_user: dict = Depends(get_current_user)):
    # Get all expenses for current user
    expenses = expenses_ref.get() or {}
    user_expenses = []
    for eid, expense in expenses.items():
        if expense.get('user_id') == current_user['id']:
            user_expenses.append({"id": eid, **expense})
    return user_expenses

@app.post("/wallets", response_model=WalletResponse)
def create_wallet(
    wallet: WalletCreate,
    current_user: dict = Depends(get_current_user)
):
    # Create wallet
    wallet_id = str(uuid.uuid4())
    wallet_data = {
        "name": wallet.name,
        "created_by": current_user['id'],
        "created_at": datetime.utcnow().isoformat(),
        "members": {current_user['id']: True}
    }
    wallets_ref.child(wallet_id).set(wallet_data)

    return {"id": wallet_id, "name": wallet.name, "created_by": current_user['id']}

@app.post("/upload-receipt")
async def upload_receipt(
    file: UploadFile = File(...),
    current_user: dict = Depends(get_current_user)
):
    try:
        # Upload to Cloudinary
        upload_result = cloudinary.uploader.upload(
            file.file,
            folder="expense_tracker_receipts",
            resource_type="auto",
            public_id=f"receipt_{uuid.uuid4().hex}",
            overwrite=True,
            use_filename=True
        )

        # Get secure URL
        cloudinary_url = upload_result.get("secure_url")

        return {
            "cloudinary_url": cloudinary_url,
            "public_id": upload_result.get("public_id"),
            "format": upload_result.get("format")
        }
    except Exception as e:
        logger.error(f"Cloudinary upload error: {e}")
        raise HTTPException(status_code=500, detail="Failed to upload receipt")

@app.post("/save-receipt", response_model=dict)
def save_receipt(
    receipt_data: ReceiptCreate,
    current_user: dict = Depends(get_current_user)
):
    # Verify user owns the expense
    expense = expenses_ref.child(receipt_data.expense_id).get()
    if not expense or expense.get('user_id') != current_user['id']:
        raise HTTPException(status_code=404, detail="Expense not found")

    # Save receipt
    receipt_id = str(uuid.uuid4())
    receipt_data = {
        "expense_id": receipt_data.expense_id,
        "cloudinary_url": receipt_data.cloudinary_url,
        "ocr_text": receipt_data.ocr_text,
        "confidence": receipt_data.confidence,
        "parsed_data": json.dumps(receipt_data.parsed_data)
    }
    receipts_ref.child(receipt_id).set(receipt_data)

    return {"status": "success", "receipt_id": receipt_id}

@app.get("/")
def health_check():
    return {"status": "running", "version": "1.0", "timestamp": datetime.utcnow()}
