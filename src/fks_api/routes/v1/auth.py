import hashlib
import re
import secrets
import time
from datetime import datetime, timedelta
from typing import Any, Dict, List, Optional

from core.config import settings
from fastapi import APIRouter, Depends, HTTPException, Request, status
from fastapi.security import OAuth2PasswordBearer, OAuth2PasswordRequestForm
from framework.middleware.auth import (
    authenticate_user,
    create_access_token,
    get_auth_token,
)
from passlib.context import CryptContext
from pydantic import BaseModel, Field, validator

# Setup password context for hashing
pwd_context = CryptContext(schemes=["bcrypt"], deprecated="auto")


# Models for request/response
class Token(BaseModel):
    """Token response with access and refresh tokens."""

    access_token: str
    refresh_token: str
    token_type: str
    expires_in: int


class RefreshRequest(BaseModel):
    """Request to refresh an access token."""

    refresh_token: str


class UserCredentials(BaseModel):
    """User login credentials with validation."""

    username: str
    password: str

    @validator("password")
    def password_complexity(cls, v):
        """Validate password complexity."""
        min_length = 8
        if len(v) < min_length:
            raise ValueError(f"Password must be at least {min_length} characters")
        if not re.search(r"[A-Z]", v):
            raise ValueError("Password must contain at least one uppercase letter")
        if not re.search(r"[a-z]", v):
            raise ValueError("Password must contain at least one lowercase letter")
        if not re.search(r"[0-9]", v):
            raise ValueError("Password must contain at least one number")
        if not re.search(r"[^A-Za-z0-9]", v):
            raise ValueError("Password must contain at least one special character")
        return v


class UserRegister(UserCredentials):
    """User registration data."""

    email: str
    full_name: Optional[str] = None

    @validator("email")
    def email_must_be_valid(cls, v):
        """Validate email format."""
        if not re.match(r"^[a-zA-Z0-9_.+-]+@[a-zA-Z0-9-]+\.[a-zA-Z0-9-.]+$", v):
            raise ValueError("Invalid email format")
        return v


class UserInfo(BaseModel):
    """User information returned to client."""

    username: str
    email: Optional[str] = None
    full_name: Optional[str] = None
    roles: List[str] = Field(default_factory=list)
    last_login: Optional[datetime] = None


# Create router
router = APIRouter(
    prefix="/auth",
    tags=["authentication"],
)

# Rate limiting configuration
# In a production app, use Redis or a similar database for distributed rate limiting
rate_limits = {}


# Simple in-memory user and token database for demonstration
# In a real application, these would be stored in a database
USERS = {
    "admin": {
        "username": "admin",
        "email": "admin@example.com",
        "full_name": "Admin User",
        # Hashed version of "Admin@123" - in production, generate these properly
        "hashed_password": (
            "$2b$12$EixZaYVK1fsbw1ZfbX3OXePaWxn96p36WQoeG6Lruj3vjPGga31lW"
        ),
        "disabled": False,
        "roles": ["admin", "user"],
        "last_login": None,
    },
    "demo": {
        "username": "demo",
        "email": "demo@example.com",
        "full_name": "Demo User",
        # Hashed version of "Demo@123" - in production, generate these properly
        "hashed_password": (
            "$2b$12$cZvASDz0Fjf7MlAnjzLRt.Os5stPauRPzDfYFcj1A0JCT3ZnXIOOO"
        ),
        "disabled": False,
        "roles": ["user"],
        "last_login": None,
    },
}

# Token storage
REFRESH_TOKENS = {}  # Maps refresh tokens to usernames
TOKEN_BLACKLIST = set()  # Stores invalidated tokens


def check_rate_limit(username: str, limit: int = 5, window: int = 60) -> bool:
    """
    Check if user has exceeded rate limit.

    Args:
        username: Username to check
        limit: Maximum number of attempts
        window: Time window in seconds

    Returns:
        True if rate limit is not exceeded, False otherwise
    """
    now = time.time()
    user_attempts = rate_limits.get(username, [])

    # Remove attempts outside the time window
    user_attempts = [t for t in user_attempts if now - t < window]

    # Check if rate limit is exceeded
    if len(user_attempts) >= limit:
        return False

    # Add new attempt
    user_attempts.append(now)
    rate_limits[username] = user_attempts
    return True


def verify_password(plain_password: str, hashed_password: str) -> bool:
    """
    Verify a password against a hash using secure hashing.

    Args:
        plain_password: Plain text password
        hashed_password: Hashed password

    Returns:
        True if password is valid
    """
    return pwd_context.verify(plain_password, hashed_password)


def get_password_hash(password: str) -> str:
    """
    Hash a password using secure hashing.

    Args:
        password: Plain text password

    Returns:
        Hashed password
    """
    return pwd_context.hash(password)


def get_user(username: str) -> Optional[dict]:
    """
    Get a user by username.

    Args:
        username: Username

    Returns:
        User data or None if not found
    """
    # In a real application, get user from database
    return USERS.get(username)


def create_refresh_token(username: str) -> str:
    """
    Create a new refresh token for a user.

    Args:
        username: Username

    Returns:
        Refresh token
    """
    # Generate a secure random token
    token = secrets.token_urlsafe(32)

    # Store in refresh token database
    REFRESH_TOKENS[token] = {
        "username": username,
        "created_at": datetime.now(),
        "expires_at": datetime.now() + timedelta(days=14),  # 14-day expiry
    }

    return token


def get_user_from_refresh_token(refresh_token: str) -> Optional[dict]:
    """
    Get a user from a refresh token.

    Args:
        refresh_token: Refresh token

    Returns:
        User data or None if invalid
    """
    token_data = REFRESH_TOKENS.get(refresh_token)

    if not token_data:
        return None

    # Check if token has expired
    if datetime.now() > token_data["expires_at"]:
        # Remove expired token
        REFRESH_TOKENS.pop(refresh_token, None)
        return None

    # Get user
    return get_user(token_data["username"])


def invalidate_refresh_token(refresh_token: str) -> bool:
    """
    Invalidate a refresh token.

    Args:
        refresh_token: Refresh token

    Returns:
        True if token was invalidated, False otherwise
    """
    if refresh_token in REFRESH_TOKENS:
        REFRESH_TOKENS.pop(refresh_token)
        return True
    return False


def update_last_login(username: str) -> None:
    """
    Update the last login timestamp for a user.

    Args:
        username: Username
    """
    if username in USERS:
        USERS[username]["last_login"] = datetime.now()


# Middleware for rate limiting
async def rate_limit_middleware(request: Request):
    """
    Rate limiting middleware for authentication endpoints.

    Returns a 429 status code if rate limit is exceeded.
    """
    if request.url.path.startswith("/auth/token") or request.url.path.startswith(
        "/auth/login"
    ):
        # Extract username from request
        if request.method == "POST":
            try:
                body = await request.json()
                username = body.get("username", "anonymous")
            except:
                username = "anonymous"

            if not check_rate_limit(username):
                raise HTTPException(
                    status_code=status.HTTP_429_TOO_MANY_REQUESTS,
                    detail="Too many login attempts. Please try again later.",
                )

    return None


# Routes
@router.post("/token", response_model=Token)
async def login_for_access_token(form_data: OAuth2PasswordRequestForm = Depends()):
    """
    OAuth2 compatible token login, get an access token for future requests.

    Args:
        form_data: OAuth2 form with username and password

    Returns:
        Access token information
    """
    user = get_user(form_data.username)

    if not user or not verify_password(form_data.password, user["hashed_password"]):
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Incorrect username or password",
            headers={"WWW-Authenticate": "Bearer"},
        )

    if user.get("disabled", False):
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST, detail="User account is disabled"
        )

    # Update last login
    update_last_login(user["username"])

    # Create access token
    access_token_expires = timedelta(minutes=30)
    access_token = create_access_token(
        data={
            "sub": user["username"],
            "roles": user.get("roles", ["user"]),
            "aud": "api:access",
            "iss": "auth-service",
        },
        expires_delta=access_token_expires,
    )

    # Create refresh token
    refresh_token = create_refresh_token(user["username"])

    return {
        "access_token": access_token,
        "refresh_token": refresh_token,
        "token_type": "bearer",
        "expires_in": access_token_expires.total_seconds(),
    }


@router.post("/login", response_model=Token)
async def login(credentials: UserCredentials):
    """
    Login with username and password.

    Args:
        credentials: User credentials

    Returns:
        Access token information
    """
    user = get_user(credentials.username)

    if not user or not verify_password(credentials.password, user["hashed_password"]):
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Incorrect username or password",
            headers={"WWW-Authenticate": "Bearer"},
        )

    if user.get("disabled", False):
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST, detail="User account is disabled"
        )

    # Update last login
    update_last_login(user["username"])

    # Create access token
    access_token_expires = timedelta(minutes=30)
    access_token = create_access_token(
        data={
            "sub": user["username"],
            "roles": user.get("roles", ["user"]),
            "aud": "api:access",
            "iss": "auth-service",
        },
        expires_delta=access_token_expires,
    )

    # Create refresh token
    refresh_token = create_refresh_token(user["username"])

    return {
        "access_token": access_token,
        "refresh_token": refresh_token,
        "token_type": "bearer",
        "expires_in": access_token_expires.total_seconds(),
    }


@router.post("/refresh", response_model=Token)
async def refresh_access_token(refresh_request: RefreshRequest):
    """
    Refresh an access token using a refresh token.

    Args:
        refresh_request: Request with refresh token

    Returns:
        New access token information
    """
    user = get_user_from_refresh_token(refresh_request.refresh_token)

    if not user:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid refresh token or token expired",
        )

    if user.get("disabled", False):
        # Invalidate the refresh token
        invalidate_refresh_token(refresh_request.refresh_token)

        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST, detail="User account is disabled"
        )

    # Create new access token
    access_token_expires = timedelta(minutes=30)
    access_token = create_access_token(
        data={
            "sub": user["username"],
            "roles": user.get("roles", ["user"]),
            "aud": "api:access",
            "iss": "auth-service",
        },
        expires_delta=access_token_expires,
    )

    # Create new refresh token
    new_refresh_token = create_refresh_token(user["username"])

    # Invalidate old refresh token
    invalidate_refresh_token(refresh_request.refresh_token)

    return {
        "access_token": access_token,
        "refresh_token": new_refresh_token,
        "token_type": "bearer",
        "expires_in": access_token_expires.total_seconds(),
    }


@router.post("/logout", status_code=status.HTTP_204_NO_CONTENT)
async def logout(refresh_token: RefreshRequest, token: str = Depends(get_auth_token)):
    """
    Logout a user by invalidating their tokens.

    Args:
        refresh_token: Refresh token to invalidate
        token: Access token
    """
    # Add access token to blacklist
    TOKEN_BLACKLIST.add(token)

    # Invalidate refresh token
    invalidate_refresh_token(refresh_token.refresh_token)

    return None


@router.post("/register", response_model=UserInfo, status_code=status.HTTP_201_CREATED)
async def register_user(user_data: UserRegister):
    """
    Register a new user.

    Args:
        user_data: User registration data

    Returns:
        New user information
    """
    # Check if username already exists
    if user_data.username in USERS:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST, detail="Username already exists"
        )

    # Check if email already exists
    for user in USERS.values():
        if user.get("email") == user_data.email:
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST, detail="Email already exists"
            )

    # Create new user
    hashed_password = get_password_hash(user_data.password)

    # In a real app, save to database
    USERS[user_data.username] = {
        "username": user_data.username,
        "email": user_data.email,
        "full_name": user_data.full_name,
        "hashed_password": hashed_password,
        "disabled": False,
        "roles": ["user"],
        "last_login": None,
    }

    return UserInfo(
        username=user_data.username,
        email=user_data.email,
        full_name=user_data.full_name,
        roles=["user"],
    )


@router.get("/me", response_model=UserInfo)
async def get_current_user(token: str = Depends(get_auth_token)):
    """
    Get information about the current authenticated user.

    Args:
        token: Authentication token

    Returns:
        User information
    """
    # Check if token is blacklisted
    if token in TOKEN_BLACKLIST:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Token has been invalidated",
            headers={"WWW-Authenticate": "Bearer"},
        )

    payload = authenticate_user(token)
    username = payload.get("sub")

    if not username:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid authentication credentials",
            headers={"WWW-Authenticate": "Bearer"},
        )

    user = get_user(username)

    if not user:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND, detail="User not found"
        )

    return UserInfo(
        username=user["username"],
        email=user.get("email"),
        full_name=user.get("full_name"),
        roles=user.get("roles", ["user"]),
        last_login=user.get("last_login"),
    )


@router.put("/password", status_code=status.HTTP_204_NO_CONTENT)
async def change_password(
    old_password: str, new_password: str, token: str = Depends(get_auth_token)
):
    """
    Change the user's password.

    Args:
        old_password: Current password
        new_password: New password
        token: Authentication token
    """
    payload = authenticate_user(token)
    username = payload.get("sub")

    if not username:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid authentication credentials",
            headers={"WWW-Authenticate": "Bearer"},
        )

    user = get_user(username)

    if not user:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND, detail="User not found"
        )

    # Verify old password
    if not verify_password(old_password, user["hashed_password"]):
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST, detail="Incorrect current password"
        )

    # Validate new password
    try:
        UserCredentials(username=username, password=new_password)
    except ValueError as e:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail=str(e))

    # Update password
    user["hashed_password"] = get_password_hash(new_password)

    return None


# Register middleware
def setup_middleware(app):
    """
    Register middleware for authentication routes.

    Args:
        app: FastAPI application
    """
    app.middleware("http")(rate_limit_middleware)
