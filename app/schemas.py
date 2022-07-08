"""
Schemas
"""
from pydantic import BaseModel, root_validator, validator
from typing import Optional


class Response(BaseModel):
    success: bool
    detail: str = None


class CreateUser(BaseModel):
    username: str
    firstname: str
    lastname: str
    email: str
    password: str
    admin: bool
    path_whitelist: Optional[str]
    path_blacklist: Optional[str]
    topic_whitelist: Optional[str]
    topic_blacklist: Optional[str]

    class Config:
        orm_mode = True


class UserOut(BaseModel):
    id: int
    username: str
    firstname: str
    lastname: str
    email: str
    admin: bool
    path_whitelist: str = None
    path_blacklist: str = None
    topic_whitelist: str = None
    topic_blacklist: str = None

    class Config:
        orm_mode = True


class ModifyUser(BaseModel):
    firstname: str = None
    lastname: str = None
    email: str = None
    password: str = None
    admin: bool = None
    path_whitelist: str = None
    path_blacklist: str = None
    topic_whitelist: str = None
    topic_blacklist: str = None

    @root_validator
    def check_at_least_one(cls, values):
        if all([value is None for value in values.values()]):
            raise ValueError("The request body should contain at least one field.")
        return values
