"""Crow's Nest Auth microservice"""
import os
import logging
from typing import Dict, Optional, Tuple
from datetime import datetime, timedelta
import re
from urllib import parse
import sys

import uvicorn
from fastapi import FastAPI, Depends, Request, Response, HTTPException
from fastapi.responses import JSONResponse
from fastapi.security import OAuth2PasswordRequestForm
from jose import jwt
from jose.exceptions import JWTError, ExpiredSignatureError, JWTClaimsError
from passlib.context import CryptContext
from environs import Env
from databases import Database
from sqlalchemy import create_engine
from starlette.responses import RedirectResponse


# pylint: disable=import-error, relative-beyond-top-level
from models import users, User, Base
from oauth2_password_bearer_cookie import OAuth2PasswordBearerOrCookie

from utils import mqtt_match

LOGGER = logging.getLogger(__name__)

# Reading config from environment variables
env = Env()

ACCESS_COOKIE_DOMAIN = env("ACCESS_COOKIE_DOMAIN")
ACCESS_COOKIE_NAME = env("ACCESS_COOKIE_NAME", "crowsnest-auth-access")
ACCESS_COOKIE_SECURE = env.bool("ACCESS_COOKIE_SECURE", False)
ACCESS_COOKIE_HTTPONLY = env.bool("ACCESS_COOKIE_HTTPONLY", True)
ACCESS_COOKIE_SAMESITE = env(
    "ACCESS_COOKIE_SAMESITE", "lax", validate=lambda s: s in ["lax", "strict", "none"]
)
ACCESS_TOKEN_EXPIRE_MINUTES = env.int("ACCESS_TOKEN_EXPIRE_MINUTES", 30)

JWT_TOKEN_SECRET = env("JWT_TOKEN_SECRET", os.urandom(24))

USER_DATABASE_URL = env("USER_DATABASE_URL")
ADMIN_USER_USERNAME = env("ADMIN_USERNAME", "admin")
ADMIN_USER_PASSWORD = env("ADMIN_USER_PASSWORD")
BASE_URL = env("BASE_URL")

# Setting up app and other context
app = FastAPI(root_path=BASE_URL)
oauth2_scheme = OAuth2PasswordBearerOrCookie(
    tokenUrl="login", cookie_name=ACCESS_COOKIE_NAME
)
pwd_context = CryptContext(schemes=["bcrypt"], deprecated="auto")


# Initialize async connection to database for any further usage
database = Database(USER_DATABASE_URL)

# class RequiresLoginException(Exception):
#    """Exception raised when login is required."""


@app.on_event("startup")
async def startup():
    """Run during startup of this application"""

    # Database initial setup using sqlalchemy
    Base.metadata.create_all(create_engine(USER_DATABASE_URL))

    # Connect with actual connection we will use from here on forwards
    await database.connect()

    # Create admin user
    query = users.select().where(User.username == ADMIN_USER_USERNAME)
    admin_user: User = await database.fetch_one(query)

    hashed_password = pwd_context.hash(ADMIN_USER_PASSWORD)
    if admin_user:
        query = (
            users.update()
            .where(User.username == ADMIN_USER_USERNAME)
            .values(hashed_password=hashed_password)
        )
        await database.execute(query)

    else:
        query = users.insert().values(
            username=ADMIN_USER_USERNAME, hashed_password=hashed_password
        )
        await database.execute(query)


@app.on_event("shutdown")
async def shutdown():
    """Run during shutdown of this application"""
    await database.disconnect()


## JWY utility functions ##


def create_jwt_token(user: User, exp: timedelta = None) -> str:
    """Generate a JWT token string from a User instance

    Args:
        user (User): The User instance to use as a basis
        exp (timedelta, optional): Validity time. Defaults to None.

    Returns:
        str: A Json Web Token
    """
    claims = {
        "sub": str(user.id),
        "iat": (now := datetime.utcnow()),
    }

    if exp:
        claims.update({"exp": now + exp})

    # Add path whitelist/blacklist and topic whitelist/blacklist
    if user.path_whitelist:
        claims.update({"path_whitelist": user.path_whitelist})
    if user.path_blacklist:
        claims.update({"path_blacklist": user.path_blacklist})

    return jwt.encode(claims, JWT_TOKEN_SECRET, algorithm="HS256")


async def get_credentials(
    token_tuple: Tuple[str, str] = Depends(oauth2_scheme)
) -> Dict:
    """Decode claims from a token"""
    # pylint: disable=raise-missing-from
    token_type, token = token_tuple

    if not token:
        return {
            "valid": False,
            "message": "Login necessary" if token_type == "cookie" else "Missing token",
            "claims": {},
            "token_type": token_type,
            "token": "",
        }

    try:
        claims = jwt.decode(token, JWT_TOKEN_SECRET, algorithms=["HS256"])
        message = ""
        valid = True
    except ExpiredSignatureError as exc:
        LOGGER.exception(str(exc))
        claims = {}
        message = "Expired signature."
        valid = False
    except JWTClaimsError as exc:
        LOGGER.exception(str(exc))
        claims = {}
        message = "Invalid claims"
        valid = False
    except JWTError as exc:
        LOGGER.exception(str(exc))
        claims = {}
        message = "Invalid signatrue"
        valid = False

    return {
        "valid": valid,
        "message": message,
        "claims": claims,
        "token_type": token_type,
        "token": token,
    }


async def get_user_from_claims(claims: Dict) -> User:
    """Fetch the User from the user database using the information provided in
    the decoded claims from a JWT token

    Args:
        claims (Dict): The claims as decoded from a JWT token

    Returns:
        User: A user instance
    """
    user_id = claims.get("sub")
    query = users.select().where(User.id == int(user_id))
    return User.from_record(await database.fetch_one(query))


## Routes ##


@app.post("/login")
async def login(form_data: OAuth2PasswordRequestForm = Depends()):
    """Login a user"""

    username: str = form_data.username
    password: str = form_data.password

    # Query database
    query = users.select().where(User.username == username)
    record = await database.fetch_one(query)
    if not record:
        raise HTTPException(401, "Could not validate credentials")

    user = User.from_record(record)

    # Compare credentials
    if not pwd_context.verify(password, user.hashed_password):
        raise HTTPException(401, "Could not validate credentials")

    # Create token
    jwt_token: str = create_jwt_token(
        user, timedelta(minutes=ACCESS_TOKEN_EXPIRE_MINUTES)
    )

    # Create response with cookie and return
    response = JSONResponse({"token": jwt_token})
    response.set_cookie(
        key=ACCESS_COOKIE_NAME,
        value=jwt_token,
        secure=ACCESS_COOKIE_SECURE,
        httponly=ACCESS_COOKIE_HTTPONLY,
        samesite=ACCESS_COOKIE_SAMESITE,
        domain=ACCESS_COOKIE_DOMAIN,
    )
    return response


@app.post("/logout")
async def logout(response: Response, credentials: Dict = Depends(get_credentials)):
    """Logout user

    Args:
        response (Response): The response objet
        _ (Dict, optional): To authenticate the user. Defaults to get_credentials.
    """
    if credentials["valid"] and credentials["token_type"] == "cookie":
        response.delete_cookie(ACCESS_COOKIE_NAME)
    response.status_code = 200
    return response


# pylint: disable=unused-argument
@app.get("/status")
async def status(request: Request, credentials: Dict = Depends(get_credentials)):
    """Check the user is logged in"""

    if credentials["valid"] and credentials["token_type"] == "cookie":
        user = await get_user_from_claims(credentials["claims"])
        return JSONResponse({"logged": True, "username": user.username})

    return JSONResponse({"logged": False})


# pylint: enable=unused-argument


def reject_request(
    request: Request, token_type: str, message: str, status_code: Optional[int] = 401
):
    """If token_type is not a cookie, raise an HTTP error, otherwise redirect with url parametrs"""

    if token_type != "cookie":
        raise HTTPException(status_code, message)

    uri = request.headers.get("X-Forwarded-Uri", "")
    redirect_url = (
        "http://"
        + ACCESS_COOKIE_DOMAIN
        + "/auth?url="
        + parse.quote("http://" + ACCESS_COOKIE_DOMAIN + uri)
        + "&message="
        + parse.quote(message)
    )
    return RedirectResponse(url=redirect_url)


@app.get("/verify")
async def verify(request: Request, credentials: Dict = Depends(get_credentials)):
    """Authenticate and authorize a request according to Traefik ForwardAuth scheme

    Expects the following headers to be populated:
    - X-Forwarded-Host
    - X-Forwarded-Uri
    """
    token_type = credentials["token_type"]

    if not credentials["valid"]:
        return reject_request(request, token_type, credentials["message"])

    host = request.headers.get("X-Forwarded-Host")
    uri = request.headers.get("X-Forwarded-Uri")

    if not host or not uri:
        msg = "Missing required X-Forwarded-Headers"
        LOGGER.error("%s\n%s\n%s", msg, request.client, request.headers)
        return reject_request(request, token_type, msg)

    claims = credentials["claims"]

    print("Here are the claims")
    print(credentials)

    # Hit database for long-lived tokens
    if claims.get("exp") is None:
        user = await get_user_from_claims(claims)
        if user.token != credentials["token"]:
            msg = "Long life token is not valid!"
            LOGGER.error("%s\n%s\n%s", msg, request.client, request.headers)
            return reject_request(request, token_type, msg, status_code=403)

    # ACL checks
    if paths := claims.get("path_whitelist"):
        accepted = False
        for path in paths:
            if re.match(path, uri):
                accepted = True
        if not accepted:
            return reject_request(
                request, token_type, f"Access is not allowed to {uri}", status_code=403
            )

    if paths := claims.get("path_blacklist"):
        accepted = True
        for path in paths:
            if re.match(path, uri):
                accepted = False

        if not accepted:
            return reject_request(
                request, token_type, f"Access is not allowed to {uri}", status_code=403
            )

    # Accepted!
    return JSONResponse("Access allowed!")


@app.get("/verify_emqx")
async def verify_emqx(
    username: str,
    topic: str,
):
    """Authenticate and authorize a request according to EMQX HTTP ACL plugin"""
    query = users.select().where(User.username == username)
    record = await database.fetch_one(query)
    if not record:
        raise HTTPException(403, "Access not allowed")

    user = User.from_record(record)

    # ACL checks
    if patterns := user.topic_whitelist:
        accepted = False
        for pattern in patterns:
            if mqtt_match(pattern, topic):
                accepted = True

        if not accepted:
            raise HTTPException(403, f"Access is not allowed to {topic}")

    if patterns := user.topic_blacklist:
        accepted = True
        for pattern in patterns:
            if mqtt_match(pattern, topic):
                accepted = False

        if not accepted:
            raise HTTPException(403, f"Access is not allowed to {topic}")

    # Accepted!
    return JSONResponse("Authorized")


# Long-lived tokens
@app.get("/token")
async def get_token(claims: Dict = Depends(get_credentials)) -> str:
    """Get the long-life-token of this user"""
    user = await get_user_from_claims(claims)

    if token := user.token:
        return token

    raise HTTPException(404, "No long-life-token available!")


@app.post("/token")
async def create_token(claims: Dict = Depends(get_credentials)) -> Dict:
    """Generate a new long-life-token"""
    user = await get_user_from_claims(claims)

    jwt_token = create_jwt_token(user, None)

    query = users.update().where(User.id == user.id).values(token=jwt_token)
    await database.execute(query)

    return {"token": jwt_token}


@app.delete("/token")
async def delete_token(claims: Dict = Depends(get_credentials)):
    """Delete the long-life-token of this user"""
    user = await get_user_from_claims(claims)

    query = users.update().where(User.id == user.id).values(token=None)
    await database.execute(query)

    return JSONResponse("Token deleted")


if __name__ == "__main__":

    if len(sys.argv) > 1:
        if sys.argv[1] == "-dev":
            # export ACCESS_COOKIE_DOMAIN="localhost"
            uvicorn.run("main:app", host="127.0.0.1", port=8000, reload=True)
        else:
            raise RuntimeError("Unrecognized argument.")
    else:
        uvicorn.run("main:app", host="0.0.0.0", port=80, reload=False)
