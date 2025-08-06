# database.py (SQLAlchemy models)
from sqlalchemy import Column, String, Numeric, DateTime, ForeignKey, UUID
from sqlalchemy.orm import relationship
from sqlalchemy.ext.declarative import declarative_base
import uuid

Base = declarative_base()

class User(Base):
    __tablename__ = 'users'
    id = Column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    email = Column(String(255), unique=True, index=True)
    password_hash = Column(String)
    name = Column(String(100))
    created_at = Column(DateTime, server_default=func.now())
    expenses = relationship("Expense", back_populates="user")

class SharedWallet(Base):
    __tablename__ = 'shared_wallets'
    id = Column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    name = Column(String(100))
    created_by = Column(UUID, ForeignKey('users.id'))
    members = relationship("WalletMember", back_populates="wallet")

class WalletMember(Base):
    __tablename__ = 'wallet_members'
    wallet_id = Column(UUID, ForeignKey('shared_wallets.id'), primary_key=True)
    user_id = Column(UUID, ForeignKey('users.id'), primary_key=True)
    wallet = relationship("SharedWallet", back_populates="members")

class Expense(Base):
    __tablename__ = 'expenses'
    id = Column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    user_id = Column(UUID, ForeignKey('users.id'))
    wallet_id = Column(UUID, ForeignKey('shared_wallets.id'), nullable=True)
    amount = Column(Numeric(10, 2))
    category = Column(String(50))
    description = Column(String)
    date = Column(DateTime)
    user = relationship("User", back_populates="expenses")
    receipt = relationship("Receipt", uselist=False, back_populates="expense")

class Receipt(Base):
    __tablename__ = 'receipts'
    id = Column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    expense_id = Column(UUID, ForeignKey('expenses.id'))
    s3_url = Column(String)
    ocr_text = Column(String)
    confidence = Column(Numeric)
    parsed_data = Column(JSONB)
    expense = relationship("Expense", back_populates="receipt")
