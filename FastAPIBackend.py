# main.py
from fastapi import FastAPI, Depends, HTTPException
from fastapi.security import OAuth2PasswordBearer
from pydantic import BaseModel
from database import SessionLocal, engine, User, Expense, SharedWallet
import bcrypt
import uuid

app = FastAPI()
oauth2_scheme = OAuth2PasswordBearer(tokenUrl="token")

# Pydantic models
class UserCreate(BaseModel):
    email: str
    password: str
    name: str = None

class ExpenseCreate(BaseModel):
    amount: float
    category: str
    date: str
    description: str = None
    wallet_id: uuid.UUID = None

# Dependency
def get_db():
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()

# Auth helper
def verify_password(plain_password, hashed_password):
    return bcrypt.checkpw(plain_password.encode(), hashed_password.encode())

def get_password_hash(password):
    return bcrypt.hashpw(password.encode(), bcrypt.gensalt()).decode()

# Routes
@app.post("/register")
def register(user: UserCreate, db: Session = Depends(get_db)):
    if db.query(User).filter(User.email == user.email).first():
        raise HTTPException(status_code=400, detail="Email already registered")

    hashed_password = get_password_hash(user.password)
    db_user = User(
        id=uuid.uuid4(),
        email=user.email,
        password_hash=hashed_password,
        name=user.name
    )
    db.add(db_user)
    db.commit()
    return {"id": db_user.id}

@app.post("/expenses")
def create_expense(
    expense: ExpenseCreate,
    token: str = Depends(oauth2_scheme),
    db: Session = Depends(get_db)
):
    # Verify token and get user
    user = verify_token(token)  # Implement JWT verification
    if not user:
        raise HTTPException(status_code=401, detail="Invalid token")

    # Check wallet membership if provided
    if expense.wallet_id:
        wallet_member = db.query(WalletMember).filter(
            WalletMember.wallet_id == expense.wallet_id,
            WalletMember.user_id == user.id
        ).first()
        if not wallet_member:
            raise HTTPException(status_code=403, detail="Not a wallet member")

    new_expense = Expense(
        id=uuid.uuid4(),
        user_id=user.id,
        wallet_id=expense.wallet_id,
        amount=expense.amount,
        category=expense.category,
        description=expense.description,
        date=expense.date
    )
    db.add(new_expense)
    db.commit()
    return {"id": new_expense.id}

# Add more endpoints for wallets, receipts, queries
