from fastapi import APIRouter, HTTPException, Request, status
from sqlalchemy import select

from app.models import User
from app.routes.deps import CurrentUser, DbSession
from app.schemas.auth import LoginRequest, RegisterRequest, TokenResponse, UserRead
from app.schemas.common import MessageResponse
from app.services.audit import record_audit
from app.services.rate_limit import auth_rate_limiter
from app.services.security import create_access_token, hash_password, verify_password

router = APIRouter(prefix="/auth", tags=["auth"])


def _client_ip(request: Request) -> str:
    forwarded = request.headers.get("x-forwarded-for")
    if forwarded:
        return forwarded.split(",")[0].strip()
    return request.client.host if request.client else "unknown"


@router.post("/register", response_model=UserRead, status_code=status.HTTP_201_CREATED)
def register(payload: RegisterRequest, request: Request, db: DbSession) -> User:
    ip_address = _client_ip(request)
    if not auth_rate_limiter.allow(f"register:{ip_address}:{payload.email.lower()}"):
        raise HTTPException(status_code=status.HTTP_429_TOO_MANY_REQUESTS, detail="Too many registration attempts. Try again later.")
    existing = db.scalar(select(User).where(User.email == payload.email.lower()))
    if existing:
        record_audit(db, "auth.register_conflict", None, "user", existing.id, ip_address, {"email": payload.email.lower()})
        db.commit()
        raise HTTPException(status_code=status.HTTP_409_CONFLICT, detail="Email is already registered.")

    user = User(
        email=payload.email.lower(),
        full_name=payload.full_name.strip(),
        hashed_password=hash_password(payload.password),
    )
    db.add(user)
    db.flush()
    record_audit(db, "auth.registered", user.id, "user", user.id, ip_address)
    db.commit()
    db.refresh(user)
    return user


@router.post("/login", response_model=TokenResponse)
def login(payload: LoginRequest, request: Request, db: DbSession) -> TokenResponse:
    ip_address = _client_ip(request)
    if not auth_rate_limiter.allow(f"login:{ip_address}:{payload.email.lower()}"):
        raise HTTPException(status_code=status.HTTP_429_TOO_MANY_REQUESTS, detail="Too many login attempts. Try again later.")
    user = db.scalar(select(User).where(User.email == payload.email.lower()))
    if user is None or not verify_password(payload.password, user.hashed_password):
        record_audit(db, "auth.login_failed", user.id if user else None, "user", user.id if user else None, ip_address, {"email": payload.email.lower()})
        db.commit()
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Invalid email or password.")
    record_audit(db, "auth.login_success", user.id, "user", user.id, ip_address)
    db.commit()
    return TokenResponse(access_token=create_access_token(user.id, {"role": user.role}))


@router.post("/logout", response_model=MessageResponse)
def logout() -> MessageResponse:
    return MessageResponse(message="Client token discarded. Server-side token revocation can be added later.")


@router.get("/me", response_model=UserRead)
def me(current_user: CurrentUser) -> User:
    return current_user
