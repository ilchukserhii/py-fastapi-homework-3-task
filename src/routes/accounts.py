from datetime import datetime, timezone
from typing import cast

from fastapi import APIRouter, Depends, status, HTTPException
from fastapi.security import OAuth2PasswordBearer
from sqlalchemy import select, delete
from sqlalchemy.exc import SQLAlchemyError
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy.orm import Session, joinedload

from config import get_jwt_auth_manager, get_settings, BaseAppSettings
from database import (
    get_db,
    UserModel,
    UserGroupModel,
    UserGroupEnum,
    ActivationTokenModel,
    PasswordResetTokenModel,
    RefreshTokenModel
)

from exceptions import BaseSecurityError, TokenExpiredError, InvalidTokenError

from security.interfaces import JWTAuthManagerInterface
from schemas.accounts import (
    UserRegistrationRequestSchema,
    UserRegistrationResponseSchema,
    UserActivationRequestSchema,
    MessageResponseSchema,
    PasswordResetRequestSchema,
    PasswordResetCompleteRequestSchema,
    UserLoginResponseSchema,
    UserLoginRequestSchema,
    TokenRefreshRequestSchema,
    TokenRefreshResponseSchema,
)

from security.passwords import hash_password

router = APIRouter()

oauth2_scheme = OAuth2PasswordBearer(tokenUrl="/login/")


@router.post("/register/", status_code=status.HTTP_201_CREATED, response_model=UserRegistrationResponseSchema)
async def create_user(user: UserRegistrationRequestSchema, db: AsyncSession = Depends(get_db)):
    result = await db.execute(select(UserModel).where(UserModel.email == user.email))
    db_user = result.scalar_one_or_none()
    if db_user:
        raise HTTPException(status_code=409, detail=f"A user with this email {user.email} already exists.")

    group = await db.execute(select(UserGroupModel).where(UserGroupModel.name == UserGroupEnum.USER))
    group = group.scalar_one_or_none()
    if group is None:
        raise HTTPException(status_code=500, detail="An error occurred during user creation.")

    db_add_user = UserModel.create(email=user.email, raw_password=user.password, group_id=group.id)
    activation_token = ActivationTokenModel(user=db_add_user)

    try:
        db.add(db_add_user)
        db.add(activation_token)
        await db.commit()
        await db.refresh(db_add_user)

    except SQLAlchemyError:
        await db.rollback()
        raise HTTPException(status_code=500, detail="An error occurred during user creation.")
    return db_add_user


@router.post("/activate/", response_model=MessageResponseSchema)
async def activate_user(user: UserActivationRequestSchema, db: AsyncSession = Depends(get_db)):
    user_data = await db.execute(select(UserModel).where(UserModel.email == user.email))
    db_user = user_data.scalar_one_or_none()
    if db_user is None:
        raise HTTPException(status_code=400)
    user_token = await db.execute(select(ActivationTokenModel).where(ActivationTokenModel.user == db_user))
    db_user_token = user_token.scalar_one_or_none()
    if db_user.is_active:
        raise HTTPException(status_code=400, detail="User account is already active.")

    if db_user_token is None:
        raise HTTPException(status_code=400, detail="Invalid or expired activation token.")
    print("TOKEN EXPIRES:", db_user_token.expires_at)
    print("TOKEN TZINFO:", db_user_token.expires_at.tzinfo)
    print("NOW UTC:", datetime.now(timezone.utc))
    print("TOKEN MATCH:", db_user_token.token == user.token)
    print("DB TOKEN:", repr(db_user_token.token))
    print("REQUEST TOKEN:", repr(user.token))
    if db_user_token.expires_at.replace(tzinfo=timezone.utc) < datetime.now(timezone.utc):
        raise HTTPException(status_code=400, detail="Invalid or expired activation token.")

    if db_user_token.token != user.token:
        raise HTTPException(status_code=400, detail="Invalid or expired activation token.")

    db_user.is_active = True

    try:
        await db.delete(db_user_token)
        await db.commit()
        await db.refresh(db_user)
    except SQLAlchemyError:
        await db.rollback()
        raise

    return {"message": "User account activated successfully."}


@router.post("/password-reset/request/", response_model=MessageResponseSchema)
async def reset_request(user: PasswordResetRequestSchema, db: AsyncSession = Depends(get_db)):
    user_data = await db.execute(select(UserModel).where(UserModel.email == user.email))
    db_user = user_data.scalar_one_or_none()
    if not db_user.is_active or db_user is None:
        return {"message": "If you are registered, you will receive an email with instructions."}
    pass_reset_token = await db.execute(select(PasswordResetTokenModel).where(PasswordResetTokenModel.user == db_user))
    new_pass_token = PasswordResetTokenModel(user=db_user)
    db_pass_token = pass_reset_token.scalar_one_or_none()
    if db_pass_token is not None:
        await db.delete(db_pass_token)

    await db.flush()
    db.add(new_pass_token)
    await db.commit()

    return {"message": "If you are registered, you will receive an email with instructions."}


@router.post("/reset-password/complete/", response_model=MessageResponseSchema)
async def reset_password(user: PasswordResetCompleteRequestSchema, db: AsyncSession = Depends(get_db)):
    user_data = await db.execute(select(UserModel).where(UserModel.email == user.email))
    db_user = user_data.scalar_one_or_none()
    if not db_user.is_active or db_user is None:
        raise HTTPException(status_code=400, detail="Invalid email or token.")
    pass_reset_token = await db.execute(select(PasswordResetTokenModel).where(PasswordResetTokenModel.user == db_user))
    pass_reset_token = pass_reset_token.scalar_one_or_none()

    if pass_reset_token is None:
        raise HTTPException(status_code=400, detail="Invalid email or token.")

    if pass_reset_token.token != user.token:
        await db.delete(pass_reset_token)
        await db.commit()
        raise HTTPException(status_code=400, detail="Invalid email or token.")

    if pass_reset_token.expires_at.replace(tzinfo=timezone.utc) < datetime.now(timezone.utc):
        await db.delete(pass_reset_token)
        await db.commit()
        raise HTTPException(status_code=400, detail="Invalid email or token.")

    try:
        await db.delete(pass_reset_token)
        db_user.password = user.password
        await db.commit()
    except SQLAlchemyError:
        await db.rollback()
        raise HTTPException(status_code=500, detail="An error occurred while resetting the password.")

    return {"message": "Password reset successfully."}


@router.post(
    "/login/",
    status_code=status.HTTP_201_CREATED,
    response_model=UserLoginResponseSchema
)
async def login_user(
    user: UserLoginRequestSchema,
    db: AsyncSession = Depends(get_db),
    jwt_manager: JWTAuthManagerInterface = Depends(get_jwt_auth_manager),
    settings: BaseAppSettings = Depends(get_settings)
):
    user_data = await db.execute(select(UserModel).where(UserModel.email == user.email))
    db_user = user_data.scalar_one_or_none()
    if db_user is None:
        raise HTTPException(status_code=401, detail="Invalid email or password.")
    if not db_user.verify_password(user.password):
        raise HTTPException(status_code=401, detail="Invalid email or password.")
    if not db_user.is_active:
        raise HTTPException(status_code=403, detail="User account is not activated.")
    data = {"user_id": db_user.id}
    jwt_access_token = jwt_manager.create_access_token(data)
    jwt_refresh_token = jwt_manager.create_refresh_token(data)
    user_refresh_token = RefreshTokenModel.create(
        user_id=db_user.id,
        days_valid=settings.LOGIN_TIME_DAYS,
        token=jwt_refresh_token
    )
    try:
        db.add(user_refresh_token)
        await db.commit()
    except SQLAlchemyError:
        await db.rollback()
        raise HTTPException(status_code=500, detail="An error occurred while processing the request.")

    return {
        "access_token": jwt_access_token,
        "refresh_token": jwt_refresh_token,
        "token_type": "bearer"
    }


@router.post("/refresh/", response_model=TokenRefreshResponseSchema)
async def refresh_token(
    token: TokenRefreshRequestSchema,
    db: AsyncSession = Depends(get_db),
    jwt_manager: JWTAuthManagerInterface = Depends(get_jwt_auth_manager),
):
    try:
        payload = jwt_manager.decode_refresh_token(token.refresh_token)
    except TokenExpiredError:
        raise HTTPException(status_code=400, detail="Token has expired.")
    except InvalidTokenError:
        raise HTTPException(status_code=400, detail="Invalid token.")

    token_data = await db.execute(select(RefreshTokenModel).where(token.refresh_token == RefreshTokenModel.token))
    refresh_token = token_data.scalar_one_or_none()

    if refresh_token is None:
        raise HTTPException(status_code=401, detail="Refresh token not found.")

    user_id = payload.get("user_id")
    user_data = await db.execute(select(UserModel).where(UserModel.id == user_id))
    db_user = user_data.scalar_one_or_none()
    if db_user is None:
        raise HTTPException(status_code=404, detail="User not found.")
    data = {"user_id": db_user.id}
    jwt_access_token = jwt_manager.create_access_token(data)
    return {
        "access_token": jwt_access_token
    }
