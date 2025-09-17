from fastapi import FastAPI, Depends, HTTPException
from fastapi.security import OAuth2PasswordBearer
from sqlalchemy.orm import Session
from fastapi.middleware.cors import CORSMiddleware
from db import SessionLocal, init_db, User, Important, Changes, Schedule
from pydantic import BaseModel
from passlib.context import CryptContext
from jose import jwt, JWTError
from datetime import datetime, timedelta, timezone
from contextlib import asynccontextmanager


@asynccontextmanager
async def lifespan(app: FastAPI):
    init_db()
    yield


app = FastAPI(title="Brinex API", lifespan=lifespan)

# Настройка CORS
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

SECRET_KEY = "supersecretkey"
ALGORITHM = "HS256"
ACCESS_TOKEN_EXPIRE_MINUTES = 240

pwd_context = CryptContext(schemes=["bcrypt"], deprecated="auto")


class UserCreate(BaseModel):
    login: str
    email: str
    password: str
    first_name: str
    last_name: str


class UserLogin(BaseModel):
    login: str
    password: str


class UserUpdate(BaseModel):
    profile_description: str | None = None
    avatar: str | None = None  # Добавляем поле для аватарки


class Token(BaseModel):
    access_token: str
    token_type: str


def get_db():
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()


def verify_password(plain_password: str, hashed_password: str) -> bool:
    try:
        return pwd_context.verify(plain_password, hashed_password)
    except Exception as e:
        print(f"Password verification error: {e}")
        return False


def get_password_hash(password: str) -> str:
    return pwd_context.hash(password)


def create_access_token(data: dict, expires_delta: timedelta | None = None) -> str:
    to_encode = data.copy()
    expire = datetime.now(timezone.utc) + (expires_delta or timedelta(minutes=15))
    to_encode.update({"exp": int(expire.timestamp())})
    return jwt.encode(to_encode, SECRET_KEY, algorithm=ALGORITHM)


oauth2_scheme = OAuth2PasswordBearer(tokenUrl="/login")


def get_current_user(
    token: str = Depends(oauth2_scheme), db: Session = Depends(get_db)
):
    try:
        payload = jwt.decode(token, SECRET_KEY, algorithms=[ALGORITHM])
        login: str = payload.get("sub")
        if login is None:
            raise HTTPException(status_code=401, detail="Invalid token")
        user = db.query(User).filter(User.login == login).first()
        if not user:
            raise HTTPException(status_code=401, detail="User not found")
        return user
    except JWTError:
        raise HTTPException(status_code=401, detail="Invalid token")


@app.post("/register", response_model=Token)
async def register(user_data: UserCreate, db: Session = Depends(get_db)):
    try:
        print(f"FastAPI received JSON data: {user_data}")

        # Проверяем на дубликаты
        if db.query(User).filter(User.login == user_data.login).first():
            raise HTTPException(status_code=400, detail="Login already exists")
        if db.query(User).filter(User.email == user_data.email).first():
            raise HTTPException(status_code=400, detail="Email already exists")

        # Создаем пользователя
        new_user = User(
            login=user_data.login,
            email=user_data.email,
            password=get_password_hash(user_data.password),
            first_name=user_data.first_name,
            last_name=user_data.last_name,
        )
        db.add(new_user)
        db.commit()
        db.refresh(new_user)

        # Создаем токен
        token = create_access_token(
            {"sub": new_user.login}, timedelta(minutes=ACCESS_TOKEN_EXPIRE_MINUTES)
        )
        return {"access_token": token, "token_type": "bearer"}

    except HTTPException:
        db.rollback()
        raise
    except Exception as e:
        print(f"Registration error: {e}")
        import traceback

        traceback.print_exc()
        db.rollback()
        raise HTTPException(status_code=400, detail=f"Registration failed: {str(e)}")


@app.post("/login", response_model=Token)
async def login(user_data: UserLogin, db: Session = Depends(get_db)):
    try:
        print(f"FastAPI received login data: {user_data}")

        if not all([user_data.login, user_data.password]):
            raise HTTPException(status_code=400, detail="Missing credentials")

        db_user = db.query(User).filter(User.login == user_data.login).first()
        if not db_user:
            raise HTTPException(status_code=401, detail="Incorrect login or password")

        if not verify_password(user_data.password, db_user.password):
            raise HTTPException(status_code=401, detail="Incorrect login or password")

        token = create_access_token(
            {"sub": db_user.login}, timedelta(minutes=ACCESS_TOKEN_EXPIRE_MINUTES)
        )
        return {"access_token": token, "token_type": "bearer"}

    except HTTPException:
        raise
    except Exception as e:
        print(f"Login error: {e}")
        import traceback

        traceback.print_exc()
        raise HTTPException(status_code=500, detail="Internal server error")


@app.get("/users/me")
def read_profile(current_user: User = Depends(get_current_user)):
    return {k: v for k, v in current_user.__dict__.items() if not k.startswith("_")}


@app.put("/users/me")
def update_profile(
    data: UserUpdate,
    current_user: User = Depends(get_current_user),
    db: Session = Depends(get_db),
):
    updated = False

    if data.profile_description is not None:
        current_user.profile_description = data.profile_description
        updated = True
        print(f"Updated description for {current_user.login}")

    if data.avatar is not None:
        current_user.avatar = data.avatar
        updated = True
        print(f"Updated avatar for {current_user.login}: {data.avatar}")

    if updated:
        db.commit()
        db.refresh(current_user)

    return {k: v for k, v in current_user.__dict__.items() if not k.startswith("_")}


@app.get("/events")
def list_events(db: Session = Depends(get_db)):
    important = db.query(Important).all()
    changes = db.query(Changes).all()

    return {
        "important": [item.description for item in important],
        "changes": [item.description for item in changes],
    }


@app.get("/schedule")
def get_schedule(db: Session = Depends(get_db)):
    schedule = db.query(Schedule).all()
    return [
        {
            "day": item.day,
            "lesson_number": item.lesson_number,
            "subject": item.subject,
            "room": item.room,
        }
        for item in schedule
    ]
