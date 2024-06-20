from fastapi import FastAPI, Depends, HTTPException, Response, Cookie, Header
from sqlalchemy.orm import Session
from datetime import datetime, timedelta
import jwt
from database import SessionLocal, engine
import models
import schemas
from hashing import Hash
from crud import  authenticate_user, change_password, delete_user

models.Base.metadata.create_all(bind=engine)
app = FastAPI()

# Define your secret key for JWT token signing
SECRET_KEY = "your-secret-key"
ALGORITHM = "HS256"
ACCESS_TOKEN_EXPIRE_MINUTES = 30

# Dependency to get the database session
def get_db():
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()

# Function to create access token
def create_access_token(user_id: int):
    to_encode = {"sub": user_id}
    expires_delta = timedelta(minutes=ACCESS_TOKEN_EXPIRE_MINUTES)
    expire = datetime.utcnow() + expires_delta
    to_encode.update({"exp": expire})
    encoded_jwt = jwt.encode(to_encode, SECRET_KEY, algorithm=ALGORITHM)
    return encoded_jwt

@app.post("/create_user", response_model=schemas.User)
async def create_user_endpoint(user: schemas.UserCreate, db: Session = Depends(get_db)):
    hashed_password = Hash.bcrypt(user.password)

    db_user = models.User(username=user.username, email=user.email, hashed_password=hashed_password)
    db.add(db_user)
    db.commit()
    db.refresh(db_user)
    return db_user

@app.post("/login")
async def login_endpoint(username: str, password: str, response: Response, db: Session = Depends(get_db)):
    user = authenticate_user(db, username, password)
    if not user:
        raise HTTPException(status_code=401, detail="Incorrect username or password")
  
    access_token = create_access_token(user.id)

    response.set_cookie(key="access_token", value=access_token)
    return {"access_token": access_token, "token_type": "bearer"}


@app.post("/logout")
def logout_endpoint(response: Response, access_token: str = Cookie(None)):
    if access_token is None:
        raise HTTPException(status_code=401, detail="Not logged in")
    
    try:
        token_data = jwt.decode(access_token, SECRET_KEY, algorithms=[ALGORITHM])
        username = token_data.get("sub")
        if not username:
            raise HTTPException(status_code=401, detail="Invalid token")
        response.delete_cookie(key="access_token")

        return {"message": "Logged out successfully"}
    except jwt.ExpiredSignatureError:
        raise HTTPException(status_code=401, detail="Token has expired")
    except jwt.InvalidTokenError:
        raise HTTPException(status_code=401, detail="Invalid token")
    
@app.put("/change_password")
def change_password_endpoint(new_password: str, token: str = Header(None), db: Session = Depends(get_db)):
    # Verify access token
    payload = jwt.decode(token, SECRET_KEY, algorithms=[ALGORITHM])
    if payload is None:
        raise HTTPException(status_code=401, detail="Invalid token")
    user_id = payload.get("sub")
    # Get user from database
    user = db.query(models.User).filter(models.User.id == user_id).first()
    if user is None:
        raise HTTPException(status_code=404, detail="User not found")
    # Change password
    hashed_password = Hash.bcrypt(new_password)
    user.hashed_password = hashed_password
    db.commit()
    return {"message": "Password changed successfully"}
