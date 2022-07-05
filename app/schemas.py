"""
Schemas
"""
from pydantic import BaseModel, root_validator


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


class UserOut(BaseModel):
    username: str
    firstname: str
    lastname: str
    email: str
    admin: bool
    path_whitelist: list
    path_blacklist: list
    topic_whitelist: list
    topic_blacklist: list

    class Config:
        orm_mode = True


class ModifyUser(BaseModel):
    firstname: str = None
    lastname: str = None
    email: str = None
    password: str = None
    admin: bool = None

    @root_validator
    def check_at_least_one(cls, values):
        if all([value is None for value in values.values()]):
            raise ValueError("The request body should contain at least one field.")
        return values
