from pydantic import BaseModel
from pydantic import EmailStr

class UserBase(BaseModel):
    username: str

class UserCreate(BaseModel):
    username: str
    password: str
    email:EmailStr

class User(BaseModel):
   id: int
   class Config:
       orm_mode = True