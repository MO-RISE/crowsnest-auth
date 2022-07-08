"""Crow's Nest Auth microservice"""
import os
import logging
from typing import Dict, Optional, Tuple
from datetime import datetime, timedelta
import re
from urllib import parse
from typing import List

from fastapi import FastAPI, Depends, Request, Response, HTTPException
from fastapi.responses import JSONResponse
from fastapi.security import OAuth2PasswordRequestForm, OAuth2PasswordBearer
from fastapi.middleware.cors import CORSMiddleware
from jose import jwt
from jose.exceptions import JWTError, ExpiredSignatureError, JWTClaimsError
from passlib.context import CryptContext
from environs import Env
from databases import Database
from sqlalchemy import JSON, create_engine, text
from starlette.responses import RedirectResponse

# pylint: disable=import-error, relative-beyond-top-level
from .models import users, User, Base
from . import models
from . import schemas
from .oauth2_password_bearer_cookie import OAuth2PasswordBearerOrCookie
from .utils import mqtt_match
from . import schemas
from .exceptions import VerifyException, APIException

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

database = Database(USER_DATABASE_URL)


# Allows CORS under development
if env.bool("DEVELOPMENT"):
    app.add_middleware(
        CORSMiddleware,
        allow_origins=["http://localhost:3000"],
        allow_credentials=True,
        allow_methods=["*"],
        allow_headers=["*"],
        expose_headers=["x-total-count"],
    )


# Exception Handlers


@app.exception_handler(APIException)
async def api_exception_handler(request: Request, exc: APIException):
    return JSONResponse(status_code=exc.status_code, content={"detail": exc.message})


@app.exception_handler(VerifyException)
async def redirect_or_exception_handler(request: Request, exc: VerifyException):
    uri = request.headers.get("X-Forwarded-Uri", "")
    host = request.headers.get("X-Forwarded-Host", "")

    if "/api/" in uri:
        raise APIException(exc.message)

    redirect_url = (
        "http://"
        + host
        + "/auth?url="
        + parse.quote("http://" + host + uri)
        + "&message="
        + parse.quote(exc.message)
    )
    return RedirectResponse(redirect_url)


# Dependencies


async def get_claims_from_bearer_token(
    token_tuple: Tuple[str, str] = Depends(oauth2_scheme)
) -> Tuple[dict, str]:
    """Get claims from bearer token"""
    _, token = token_tuple
    claims = None
    if token is None:
        message = "Login necessary"
    else:
        try:
            claims = jwt.decode(token, JWT_TOKEN_SECRET, algorithms=["HS256"])
            message = ""
        except ExpiredSignatureError:
            message = "Expired session"
        except JWTClaimsError:
            message = "Invalid claims"
        except JWTError:
            message = "Invalid token"
    return claims, message


async def get_user_from_bearer_token(
    claims_tuple: Tuple[User, str] = Depends(get_claims_from_bearer_token),
) -> Tuple[User, str]:
    """Get User instance from bearer token"""
    claims, message = claims_tuple
    user = None
    if claims is not None:
        try:
            query = users.select().where(User.username == claims["sub"])
            user = User.from_record(await database.fetch_one(query))
        except:
            message = "User does not exist"
    return user, message


async def verify_token(
    user_tuple: Tuple[User, str] = Depends(get_user_from_bearer_token)
):
    """Verify that the client provides a valid token"""
    user, message = user_tuple
    if not user:
        raise APIException(401, message)


async def verify_token_admin(
    user_tuple: Tuple[User, str] = Depends(get_user_from_bearer_token)
):
    """Verify that the client provides a valid token and that the corresponding user is an administrator"""
    user, message = user_tuple
    if not user:
        raise APIException(401, message)
    else:
        if not user.admin:
            raise APIException(401, "Unauthorized access")


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
            username=ADMIN_USER_USERNAME,
            firstname="Gandalf",
            lastname="The Grey",
            email="gandalf@lotr.com",
            admin=True,
            hashed_password=hashed_password,
        )
        await database.execute(query)

    # Create dummy user
    query = users.select().where(User.username == "dummy")
    dummy: User = await database.fetch_one(query)

    hashed_password = pwd_context.hash("password")
    if dummy:
        query = (
            users.update()
            .where(User.username == "dummy")
            .values(hashed_password=hashed_password)
        )
        await database.execute(query)
    else:
        query = users.insert().values(
            username="dummy",
            firstname="Dummy",
            lastname="dasdas",
            email="gandalf@lotr.com",
            admin=False,
            hashed_password=hashed_password,
            path_whitelist="/white",
        )
        await database.execute(query)


@app.on_event("shutdown")
async def shutdown():
    """Run during shutdown of this application"""
    await database.disconnect()


## JWT utility functions ##


def create_jwt_token(user: User, exp: timedelta = None) -> str:
    """Create a JSON Web Token (JWT) string from a User instance

    Args:
        user (User): The User instance,
        exp (timedelta, optional): Validity time in seconds. Defaults to None.

    Returns:
        str: A JSON Web Token
    """

    claims = {
        "sub": str(user.username),
        "iat": (now := datetime.utcnow()),
    }

    if exp:
        claims.update({"exp": now + exp})

    # Add path whitelist/blacklist and topic whitelist/blacklist
    # if user.path_whitelist:
    #    claims.update({"path_whitelist": user.path_whitelist})
    # if user.path_blacklist:
    #    claims.update({"path_blacklist": user.path_blacklist})

    return jwt.encode(claims, JWT_TOKEN_SECRET, algorithm="HS256")


async def get_credentials(
    token_tuple: Tuple[str, str] = Depends(oauth2_scheme)
) -> Dict:
    """Get credentials"""

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
    except ExpiredSignatureError:
        claims = {}
        message = "Expired session"
        LOGGER.exception(message)
        valid = False
    except JWTClaimsError:
        claims = {}
        message = "Invalid claims"
        LOGGER.exception(message)
        valid = False
    except JWTError:
        message = "Invalid token"
        LOGGER.exception(message)
        claims = {}
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
    username = claims.get("sub")
    query = users.select().where(User.username == username)
    return User.from_record(await database.fetch_one(query))


# *** Routes ****


@app.post("/login", response_model=schemas.Response)
async def login(form_data: OAuth2PasswordRequestForm = Depends()):
    """Login a user"""

    username: str = form_data.username
    password: str = form_data.password

    # Query database
    query = users.select().where(User.username == username)
    record = await database.fetch_one(query)
    if not record:
        raise HTTPException(status_code=401, detail="Wrong username or password")
    user = User.from_record(record)

    # Compare credentials
    if not pwd_context.verify(password, user.hashed_password):
        raise HTTPException(status_code=400, detail="Wrong username or password.")

    # Create token
    jwt_token: str = create_jwt_token(
        user, timedelta(minutes=ACCESS_TOKEN_EXPIRE_MINUTES)
    )

    # Create response with cookie
    response = JSONResponse(status_code=200, content={"success": True})

    # Cookie domain should not be used with localhost
    access_cookie_domain = (
        ACCESS_COOKIE_DOMAIN if "localhost" not in ACCESS_COOKIE_DOMAIN else None
    )

    # Set Cookie
    response.set_cookie(
        key=ACCESS_COOKIE_NAME,
        value=jwt_token,
        secure=ACCESS_COOKIE_SECURE,
        httponly=ACCESS_COOKIE_HTTPONLY,
        samesite=ACCESS_COOKIE_SAMESITE,
        domain=access_cookie_domain,
    )

    return response


@app.post(
    "/logout", dependencies=[Depends(verify_token)], response_model=schemas.Response
)
async def logout():
    """Logout user"""
    response = JSONResponse(status_code=200, content={"success": True})
    response.delete_cookie(ACCESS_COOKIE_NAME)
    return response


@app.get(
    "/me",
    response_model=schemas.UserOut,
    dependencies=[Depends(verify_token)],
)
async def get_me(user_tuple: Tuple[User, str] = Depends(get_user_from_bearer_token)):
    """Get the details of the current user"""
    user, _ = user_tuple
    return user


def validate_paths_text_string(text_string: str) -> bool:
    """Validate that a text string containing pahts"""
    if len(text_string) == 0:
        return True
    paths = text_string.split(",")
    for path in paths:
        if not re.match(r"/[a-z0-9/]+", path):
            return False
    return True


@app.get("/verify", response_model=schemas.Response)
async def verify_request(
    request: Request, user_tuple: Tuple[dict, str] = Depends(get_user_from_bearer_token)
):
    """Verify that the user has the permissions for the request"""

    uri = request.headers.get("X-Forwarded-Uri")
    host = request.headers.get("X-Forwarded-Host")

    if not host or not uri:
        msg = "Missing required X-Forwarded-Headers provided by Traefik"
        raise HTTPException(400, msg)

    # Get user
    user, message = user_tuple
    if not user:
        raise VerifyException(message)

    # Limit access to non-administrators
    if "admin" in uri and not user["admin"]:
        raise VerifyException(f"Unauthorized access")

    # Access Control List checks
    if user.path_whitelist:
        accepted = False
        for path in user.path_whitelist.split(","):
            if re.match(path, uri):
                accepted = True
        if not accepted:
            raise VerifyException("Unauthorized access to {uri}")

    if user.path_blacklist:
        accepted = True
        for path in user.path_blacklist.split(","):
            if re.match(path, uri):
                accepted = False

        if not accepted:
            raise VerifyException("Unauthorized access to {uri}")

    return JSONResponse(status_code=200, content={"success": True})


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


@app.get(
    "/users",
    response_model=List[schemas.UserOut],
    dependencies=[Depends(verify_token_admin)],
)
async def get_all_users(_end: int, _order: str, _sort: str, _start: int):
    query = (
        models.users.select().order_by(text(f"{_sort} {_order}")).slice(_start, _end)
    )
    user_records = [dict(user) for user in await database.fetch_all(query)]

    response = JSONResponse(user_records)
    response.headers["x-total-count"] = str(
        len(await database.fetch_all(models.users.select()))
    )
    return response


@app.get(
    "/users/{id}",
    response_model=schemas.UserOut,
    dependencies=[Depends(verify_token_admin)],
)
async def get_user_by_id(id: int):
    try:
        return models.User.from_record(
            await database.fetch_one(models.users.select().where(models.User.id == id))
        )
    except Exception as e:
        raise APIException(406, str(e))


@app.post(
    "/users",
    dependencies=[Depends(verify_token_admin)],
)
async def create_user(user: schemas.CreateUser):
    hashed_password = pwd_context.hash(user.password)
    print("Create user")
    print(user)
    print(user.path_whitelist)
    try:
        await database.execute(
            models.users.insert().values(
                username=user.username.lower(),
                firstname=user.firstname,
                lastname=user.lastname,
                email=user.lastname,
                admin=user.admin,
                hashed_password=hashed_password,
            )
        )
        return JSONResponse(status_code=200, content={"success": True})
    except Exception as e:
        raise APIException(
            406, f"User with username '{user.username.lower()}' already exists"
        )


@app.put(
    "/users/{id}",
    response_model=schemas.UserOut,
    dependencies=[Depends(verify_token_admin)],
)
async def modify_user(id: int, modifications: schemas.ModifyUser):
    print("asd")
    print(modifications.__dict__)
    mods = {k: v for k, v in modifications.__dict__.items() if v is not None}
    # If provided, hash the password
    if "password" in mods:
        mods["hashed_password"] = pwd_context.hash(modifications.password)
        del mods["password"]

    # Validate the paths_text_string
    print(mods)
    for key in [
        "path_whitelist",
        "path_blacklist",
        "topic_whitelist",
        "topic_blacklist",
    ]:
        if key in mods:
            if not validate_paths_text_string(mods[key]):
                raise HTTPException(status_code=422, detail=f"Invalid value for {key}")

    # Update user in the database
    try:
        await database.execute(
            models.users.update().where(models.User.id == id).values(**mods)
        )
    except Exception as e:
        raise APIException(406, f"User with id '{id}' does not exist")

    # Success
    return models.User.from_record(
        await database.fetch_one(models.users.select().where(models.User.id == id))
    )


@app.delete(
    "/users/{id}",
    dependencies=[
        Depends(verify_token_admin),
    ],
    response_model=schemas.Response,
)
async def delete_user(id: int):
    try:
        models.User.from_record(
            await database.fetch_one(models.users.select().where(models.User.id == id))
        )
        await database.execute(models.users.delete().where(models.User.id == id))
        return JSONResponse(status_code=200, content={"detail": "success"})
    except Exception as e:
        raise APIException(406, f"User with id '{id}' does not exist")
