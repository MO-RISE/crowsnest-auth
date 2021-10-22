import os
import regex as re
from typing import Dict
from uuid import UUID
from datetime import datetime, timedelta

import uvicorn
from fastapi import FastAPI, Depends, Request, HTTPException
from fastapi.responses import JSONResponse
from fastapi.security import OAuth2PasswordRequestFormStrict
from jose import jwt
from jose.exceptions import JWTError, ExpiredSignatureError, JWTClaimsError
from passlib.context import CryptContext
from environs import Env
from databases import Database
from sqlalchemy import create_engine

from models import User, Base
from oauth2_password_bearer_cookie import OAuth2PasswordBearerOrCookie

# Reading config from environment variables
env = Env()

ACCESS_COOKIE_DOMAIN = env("COOKIE_DOMAIN", None)
ACCESS_COOKIE_NAME = env("ACCESS_COOKIE_NAME", "crowsnest-auth-access")
ACCESS_COOKIE_SECURE = env.bool("ACCESS_COOKIE_SECURE", False)
ACCESS_COOKIE_HTTPONLY = env.bool("ACCESS_COOKIE_HTTPONLY", False)
ACCESS_COOKIE_SAMESITE = env(
    "ACCESS_COOKIE_SAMESITE", "lax", validate=lambda s: s in ["lax", "strict", "none"]
)
ACCESS_TOKEN_EXPIRE_MINUTES = env.int("ACCESS_TOKEN_EXPIRE_MINUTES", 30)
JWT_TOKEN_SECRET = env("JWT_TOKEN_SECRET", os.urandom(24))
DATABASE_URL = env("DATABASE_URL")


# Setting up app and other context
app = FastAPI()
oauth2_scheme = OAuth2PasswordBearerOrCookie(
    tokenUrl="login", cookie_name=ACCESS_COOKIE_NAME
)
pwd_context = CryptContext(schemes=["bcrypt"], deprecated="auto")


# Database initial setup using sqlalchemy
Base.metadata.create_all(
    create_engine(DATABASE_URL, connect_args={"check_same_thread": False})
)

# Initialize async connection to database for any further usage
database = Database(DATABASE_URL)


@app.on_event("startup")
async def startup():
    await database.connect()


@app.on_event("shutdown")
async def shutdown():
    await database.disconnect()


@app.post("/login")
async def login(form_data: OAuth2PasswordRequestFormStrict = Depends()):
    username: str = form_data.username
    password: str = form_data.password

    # Query database
    user = User.select()
    user_id = username
    fake_pass_hashed = pwd_context.hash(password)

    # Compare credentials
    if not pwd_context.verify(password, fake_pass_hashed):
        raise HTTPException(401, "Could not validate credentials")

    # Create token
    claims = {
        "sub": user_id,
        "iat": (now := datetime.utcnow()),
        "exp": now + timedelta(minutes=ACCESS_TOKEN_EXPIRE_MINUTES),
    }

    # Add path whitelist/blacklist and topic whitelist/blacklist

    jwt_token = jwt.encode(claims, JWT_TOKEN_SECRET, algorithm="HS256")

    # Create response with cookie and return
    response = JSONResponse("Login successful!")
    response.set_cookie(
        key=ACCESS_COOKIE_NAME,
        value=jwt_token,
        secure=ACCESS_COOKIE_SECURE,
        httponly=ACCESS_COOKIE_HTTPONLY,
        samesite=ACCESS_COOKIE_SAMESITE,
        domain=ACCESS_COOKIE_DOMAIN,
    )
    return response


async def get_claims(token: str = Depends(oauth2_scheme)):
    try:
        return jwt.decode(token, JWT_TOKEN_SECRET, algorithms=["HS256"])
    except JWTError:
        raise HTTPException(401, "Invalid signature")
    except ExpiredSignatureError:
        raise HTTPException(401, "Expired signature")
    except JWTClaimsError:
        raise HTTPException(400, "Invalid claims")


@app.get("/verify")
async def verify(request: Request, claims: Dict = Depends(get_claims)):
    host = request.headers.get("X-Forwarded-Host")
    uri = request.headers.get("X-Forwarded-Uri")

    if not host or not uri:
        raise HTTPException(400, "Missing required X-Forwarded-Headers")

    # TODO: Handle Long-lived tokens

    # ACL checks
    if paths := claims.get("path_whitelist"):
        accepted = False
        for path in paths:
            if re.match(path, uri):
                accepted = True

        if not accepted:
            raise HTTPException(403, f"Access is not allowed to {uri}")

    if paths := claims.get("path_blacklist"):
        accepted = True
        for path in paths:
            if re.match(path, uri):
                accepted = False

        if not accepted:
            raise HTTPException(403, f"Access is not allowed to {uri}")

    # Accepted!
    return JSONResponse("Access allowed!")


@app.get("/verify_emqx")
async def verify_emqx(claims: Dict = Depends(get_claims)):
    # TODO: Needs a nice way of pattern matching towards mqtt topic wildcard syntax
    pass


# Long-lived tokens
@app.get("/token")
async def get_tokens(claims: Dict = Depends(get_claims)):
    # Get from db
    # Return as json
    pass


@app.post("/token")
async def create_token(claims: Dict = Depends(get_claims)):

    # Check against database
    # Create token
    # Return raw token and UUID
    pass


@app.delete("/token")
async def delete_token(uuid: UUID, claims: Dict = Depends(get_claims)):
    # Delete from db
    pass


if __name__ == "__main__":
    uvicorn.run(app, host="0.0.0.0", port=8000)
