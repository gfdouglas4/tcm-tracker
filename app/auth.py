import pyotp
from passlib.context import CryptContext
from fastapi import Request, HTTPException, status
from sqlalchemy.orm import Session

from app.models import User

pwd_context = CryptContext(schemes=["bcrypt"], deprecated="auto")


def hash_password(password: str) -> str:
    return pwd_context.hash(password)


def verify_password(password: str, password_hash: str) -> bool:
    return pwd_context.verify(password, password_hash)


def new_totp_secret() -> str:
    return pyotp.random_base32()


def totp_uri(secret: str, username: str, issuer: str = "TCM Tracker") -> str:
    return pyotp.totp.TOTP(secret).provisioning_uri(name=username, issuer_name=issuer)


def verify_totp(secret: str, code: str) -> bool:
    if not secret or not code:
        return False
    totp = pyotp.TOTP(secret)
    # valid_window=1 allows a 30s clock-skew grace period
    return totp.verify(code.strip(), valid_window=1)


def get_current_user(request: Request, db: Session) -> User | None:
    user_id = request.session.get("user_id")
    if not user_id:
        return None
    # Fully-authenticated session requires 2FA to have been passed for this session.
    if not request.session.get("mfa_ok"):
        return None
    return db.query(User).filter(User.id == user_id, User.is_active == True).first()  # noqa: E712


def require_user(request: Request, db: Session) -> User:
    user = get_current_user(request, db)
    if not user:
        raise HTTPException(status_code=status.HTTP_303_SEE_OTHER, headers={"Location": "/login"})
    return user
