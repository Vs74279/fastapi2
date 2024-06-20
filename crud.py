# crud.py

from sqlalchemy.orm import Session
import models
from hashing import Hash

def create_user(db: Session, username: str, email: str, password: str):
    hashed_password = Hash.bcrypt(password)
    db_user = models.User(username=username, email=email, hashed_password=hashed_password)
    db.add(db_user)
    db.commit()
    db.refresh(db_user)
    return db_user

def authenticate_user(db: Session, username: str, password: str):
    user = db.query(models.User).filter(models.User.username == username).first()
    if not user or not Hash.verify(password, user.hashed_password):
        return None
    return user

def change_password(db: Session, user_id: int, new_password: str):
    user = db.query(models.User).filter(models.User.id == user_id).first()
    if not user:
        return None
    hashed_password = Hash.bcrypt(new_password)
    user.hashed_password = hashed_password
    db.commit()
    return user

def delete_user(db: Session, user_id: int):
    user = db.query(models.User).filter(models.User.id == user_id).first()
    if not user:
        return None
    db.delete(user)
    db.commit()
    return user
