from pydantic import BaseModel, EmailStr
from typing import Optional


class UserBase(BaseModel):
    email: EmailStr
    full_name: Optional[str] = None


class UserCreate(UserBase):
    password: str
    # vendrá desde el front según el rol seleccionado
    is_admin: bool = False


class UserLogin(BaseModel):
    email: EmailStr
    password: str


class UserInDB(UserBase):
    id: int
    is_active: bool
    is_admin: bool

    class Config:
        from_attributes = True  # pydantic v2


class UserPublic(UserBase):
    id: int
    is_active: bool
    is_admin: bool

    class Config:
        from_attributes = True
