from __future__ import annotations

from datetime import timedelta

from fastapi import APIRouter, Depends, HTTPException, Request, Response, status
from sqlalchemy import func, select
from sqlalchemy.ext.asyncio import AsyncSession

from app.api.deps import get_current_user
from app.core.config import get_settings
from app.db.base import utcnow
from app.db.models import User, UserSession
from app.db.session import get_db
from app.schemas.auth import (
    ChangePasswordRequest,
    LoginRequest,
    ProfileUpdateRequest,
    RegisterRequest,
    SessionResponse,
    UserResponse,
)
from app.services.security import (
    SESSION_COOKIE_NAME,
    build_session_expiry,
    generate_session_token,
    hash_password,
    hash_session_token,
    user_has_feature_access,
    verify_password,
)

router = APIRouter(prefix="/auth", tags=["auth"])


def serialize_user(user: User) -> UserResponse:
    return UserResponse(
        id=user.id,
        username=user.username,
        role=user.role,
        status=user.status,
        language=user.language,
        max_domains=user.max_domains,
        access_expires_at=user.access_expires_at,
        status_message=user.status_message,
        last_login_at=user.last_login_at,
        deleted_at=user.deleted_at,
        created_at=user.created_at,
        updated_at=user.updated_at,
    )


def build_session_payload(user: User) -> SessionResponse:
    return SessionResponse(user=serialize_user(user), has_feature_access=user_has_feature_access(user))


@router.post("/register", response_model=SessionResponse, status_code=status.HTTP_201_CREATED)
async def register(
    payload: RegisterRequest,
    response: Response,
    db: AsyncSession = Depends(get_db),
) -> SessionResponse:
    username = payload.username.strip().lower()
    existing = await db.execute(select(User).where(User.username == username))
    if existing.scalar_one_or_none():
        raise HTTPException(status_code=400, detail="Username already exists")

    total_users = int(await db.scalar(select(func.count(User.id))) or 0)
    role = "owner" if total_users == 0 else "user"
    status_value = "approved" if role == "owner" else "pending"
    status_message = None if role == "owner" else get_settings().default_pending_message
    user = User(
        username=username,
        password_hash=hash_password(payload.password),
        role=role,
        status=status_value,
        language=payload.language if payload.language in {"ru", "en"} else "ru",
        status_message=status_message,
    )
    db.add(user)
    await db.commit()
    await db.refresh(user)
    await _create_session_cookie(response, db, user, remember_me=False)
    return build_session_payload(user)


@router.post("/login", response_model=SessionResponse)
async def login(
    payload: LoginRequest,
    response: Response,
    db: AsyncSession = Depends(get_db),
) -> SessionResponse:
    settings = get_settings()
    username = payload.username.strip().lower()
    result = await db.execute(select(User).where(User.username == username, User.deleted_at.is_(None)))
    user = result.scalar_one_or_none()
    if user is None:
        raise HTTPException(status_code=401, detail="Invalid credentials")

    now = utcnow()
    if user.login_locked_until and user.login_locked_until > now:
        raise HTTPException(status_code=429, detail="Too many login attempts. Try later.")

    if not verify_password(payload.password, user.password_hash):
        user.login_failed_attempts += 1
        if user.login_failed_attempts >= settings.login_rate_limit_attempts:
            user.login_locked_until = now + timedelta(minutes=settings.login_lock_minutes)
            user.login_failed_attempts = 0
        await db.commit()
        raise HTTPException(status_code=401, detail="Invalid credentials")

    user.login_failed_attempts = 0
    user.login_locked_until = None
    user.last_login_at = now
    await db.commit()
    await db.refresh(user)
    await _create_session_cookie(response, db, user, remember_me=payload.remember_me)
    return build_session_payload(user)


@router.post("/logout")
async def logout(
    request: Request,
    response: Response,
    db: AsyncSession = Depends(get_db),
) -> dict[str, str]:
    raw_token = request.cookies.get(SESSION_COOKIE_NAME)
    if raw_token:
        token_hash = hash_session_token(raw_token)
        result = await db.execute(select(UserSession).where(UserSession.token_hash == token_hash))
        session = result.scalar_one_or_none()
        if session:
            session.revoked_at = utcnow()
            await db.commit()
    response.delete_cookie(SESSION_COOKIE_NAME)
    return {"detail": "Logged out"}


@router.get("/me", response_model=SessionResponse)
async def get_me(user: User = Depends(get_current_user)) -> SessionResponse:
    return build_session_payload(user)


@router.patch("/profile", response_model=SessionResponse)
async def update_profile(
    payload: ProfileUpdateRequest,
    db: AsyncSession = Depends(get_db),
    user: User = Depends(get_current_user),
) -> SessionResponse:
    if payload.language is not None and payload.language in {"ru", "en"}:
        user.language = payload.language
        user.updated_at = utcnow()
        await db.commit()
        await db.refresh(user)
    return build_session_payload(user)


@router.post("/change-password", response_model=SessionResponse)
async def change_password(
    payload: ChangePasswordRequest,
    db: AsyncSession = Depends(get_db),
    user: User = Depends(get_current_user),
) -> SessionResponse:
    if not verify_password(payload.current_password, user.password_hash):
        raise HTTPException(status_code=400, detail="Current password is invalid")
    user.password_hash = hash_password(payload.new_password)
    user.updated_at = utcnow()
    await db.commit()
    await db.refresh(user)
    return build_session_payload(user)


async def _create_session_cookie(
    response: Response,
    db: AsyncSession,
    user: User,
    *,
    remember_me: bool,
) -> None:
    raw_token = generate_session_token()
    expiry = utcnow() + build_session_expiry(remember_me)
    db.add(
        UserSession(
            user_id=user.id,
            token_hash=hash_session_token(raw_token),
            remember_me=remember_me,
            expires_at=expiry,
            last_used_at=utcnow(),
        )
    )
    await db.commit()
    response.set_cookie(
        SESSION_COOKIE_NAME,
        raw_token,
        httponly=True,
        samesite="lax",
        secure=get_settings().session_cookie_secure,
        expires=int(expiry.timestamp()),
    )
