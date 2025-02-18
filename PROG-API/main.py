from fastapi import FastAPI, Depends, HTTPException, Request, Form
from fastapi.security import OAuth2PasswordBearer, OAuth2PasswordRequestForm
from typing import Dict, Optional
from sqlalchemy import create_engine, Column, Integer, String, ForeignKey
from sqlalchemy.ext.declarative import declarative_base
from sqlalchemy.orm import sessionmaker, relationship, Session
from jose import jwt, JWTError
from datetime import datetime, timedelta
from starlette.middleware.base import BaseHTTPMiddleware
from fastapi.responses import JSONResponse

# 📌 Ma'lumotlar bazasi (SQLite - test.db)
DATABASE_URL = "sqlite:///./test.db"
engine = create_engine(DATABASE_URL, connect_args={"check_same_thread": False})
SessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=engine)
Base = declarative_base()

# 📌 Model - Foydalanuvchilar
class User(Base):
    __tablename__ = "users"  # Fixed: added __
    id = Column(Integer, primary_key=True, index=True)
    username = Column(String, unique=True, index=True)
    password = Column(String)
    role = Column(String)  # "superadmin", "admin", "teacher"
    branch = Column(String, nullable=True)
    group_name = Column(String, nullable=True)
    students = relationship("Student", back_populates="teacher")  # Added relationship

# 📌 Model - Talabalar
class Student(Base):
    __tablename__ = "students"  # Fixed: added __
    id = Column(Integer, primary_key=True, index=True)
    name = Column(String)
    branch = Column(String)
    group_name = Column(String)
    teacher_id = Column(Integer, ForeignKey("users.id"))
    teacher = relationship("User", back_populates="students")  # Added relationship

Base.metadata.create_all(bind=engine)

# 📌 Token sozlamalari
SECRET_KEY = "mysecretkey"
ALGORITHM = "HS256"
ACCESS_TOKEN_EXPIRE_MINUTES = 30

oauth2_scheme = OAuth2PasswordBearer(tokenUrl="token")

# 📌 Multi-tenancy Middleware
class MultiTenancyMiddleware(BaseHTTPMiddleware):
    async def dispatch(self, request: Request, call_next):
        if request.url.path in ["/token", "/register", "/docs", "/openapi.json", "/redoc"]:
            response = await call_next(request)
            return response

        try:
            auth_header = request.headers.get("Authorization")
            if not auth_header:
                return JSONResponse(
                    status_code=401,
                    content={"detail": "Authorization header missing"}
                )

            token = auth_header.split(" ")[1]
            payload = jwt.decode(token, SECRET_KEY, algorithms=[ALGORITHM])
            
            # Request state-ga user ma'lumotlarini saqlash
            request.state.user = payload
            
            response = await call_next(request)
            return response
            
        except (JWTError, IndexError):
            return JSONResponse(
                status_code=401,
                content={"detail": "Invalid token"}
            )

# 📌 FastAPI ilovasi
app = FastAPI()
app.add_middleware(MultiTenancyMiddleware)

# 📌 Database Dependency
def get_db():
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()

# 📌 Token yaratish funksiyalari
def create_access_token(data: dict, expires_delta: Optional[timedelta] = None):
    to_encode = data.copy()
    expire = datetime.utcnow() + (expires_delta or timedelta(minutes=ACCESS_TOKEN_EXPIRE_MINUTES))
    to_encode.update({"exp": expire})
    return jwt.encode(to_encode, SECRET_KEY, algorithm=ALGORITHM)

# 📌 Foydalanuvchini tekshirish
def authenticate_user(db: Session, username: str, password: str):
    user = db.query(User).filter(User.username == username, User.password == password).first()
    return user

# 📌 Joriy foydalanuvchini olish
async def get_current_user(token: str = Depends(oauth2_scheme), db: Session = Depends(get_db)):
    credentials_exception = HTTPException(
        status_code=401,
        detail="Could not validate credentials",
        headers={"WWW-Authenticate": "Bearer"},
    )
    try:
        payload = jwt.decode(token, SECRET_KEY, algorithms=[ALGORITHM])
        username: str = payload.get("sub")
        if username is None:
            raise credentials_exception
    except JWTError:
        raise credentials_exception

    user = db.query(User).filter(User.username == username).first()
    if user is None:
        raise credentials_exception
    return user

# 📌 Registratsiya
@app.post("/register")
async def register(
    username: str = Form(...),
    password: str = Form(...),
    role: str = Form(...),
    branch: str = Form(None),
    group_name: str = Form(None),
    db: Session = Depends(get_db)
):
    if role not in ["teacher"]:
        raise HTTPException(status_code=400, detail="Noto'g'ri rol tanlandi")

    existing_user = db.query(User).filter(User.username == username).first()
    if existing_user:
        raise HTTPException(status_code=400, detail="Bu username allaqachon mavjud")

    new_user = User(
        username=username,
        password=password,  # Real loyihada parolni hashlash kerak!
        role=role,
        branch=branch,
        group_name=group_name
    )
    db.add(new_user)
    db.commit()
    return {"message": f"Foydalanuvchi qo'shildi: {username}, Rol: {role}"}

# 📌 Login
@app.post("/token")
async def login(form_data: OAuth2PasswordRequestForm = Depends(), db: Session = Depends(get_db)):
    user = authenticate_user(db, form_data.username, form_data.password)
    if not user:
        raise HTTPException(status_code=400, detail="Noto'g'ri username yoki parol")

    access_token = create_access_token(
        data={
            "sub": user.username,
            "role": user.role,
            "branch": user.branch,
            "group": user.group_name
        }
    )
    return {"access_token": access_token, "token_type": "bearer"}

# 📌 Studentlarni olish
@app.get("/students")
async def get_students(current_user: User = Depends(get_current_user), db: Session = Depends(get_db)):
    if current_user.role == "teacher":
        students = db.query(Student).filter(
            Student.branch == current_user.branch,
            Student.group_name == current_user.group_name
        ).all()
    elif current_user.role == "admin":
        students = db.query(Student).filter(Student.branch == current_user.branch).all()
    elif current_user.role == "superadmin":
        students = db.query(Student).all()
    else:
        raise HTTPException(status_code=403, detail="Ruxsat berilmagan")
    
    return {"students": students}

# 📌 Student qo'shish
@app.post("/add_student")
async def add_student(
    name: str = Form(...),
    branch: str = Form(...),
    group_name: str = Form(...),
    current_user: User = Depends(get_current_user),
    db: Session = Depends(get_db)
):
    if current_user.role not in ["admin", "superadmin"]:
        raise HTTPException(status_code=403, detail="Faqat admin yoki superadmin student qo'shishi mumkin")

    teacher = db.query(User).filter(
        User.role == "teacher",
        User.branch == branch,
        User.group_name == group_name
    ).first()

    new_student = Student(
        name=name,
        branch=branch,
        group_name=group_name,
        teacher_id=teacher.id if teacher else None
    )
    db.add(new_student)
    db.commit()
    
    return {
        "message": f"Yangi student qo'shildi: {name}",
        "teacher_assigned": teacher.username if teacher else "Teacher topilmadi"
    }

# 📌 Studentni o'chirish
@app.delete("/delete_student/{student_id}")
async def delete_student(
    student_id: int,
    current_user: User = Depends(get_current_user),
    db: Session = Depends(get_db)
):
    if current_user.role not in ["admin", "superadmin"]:
        raise HTTPException(status_code=403, detail="Faqat admin yoki superadmin studentni o'chirishi mumkin")

    student = db.query(Student).filter(Student.id == student_id).first()
    if not student:
        raise HTTPException(status_code=404, detail="Student topilmadi")

    # Admin faqat o'z filialidagi studentlarni o'chira oladi
    if current_user.role == "admin" and student.branch != current_user.branch:
        raise HTTPException(status_code=403, detail="Siz faqat o'z filialingizdagi studentlarni o'chira olasiz")

    db.delete(student)
    db.commit()
    return {"message": "Student o'chirildi"}

# 📌 Admin qo'shish (faqat superadmin uchun)
@app.post("/add_admin")
async def add_admin(
    username: str = Form(...),
    password: str = Form(...),
    branch: str = Form(...),
    current_user: User = Depends(get_current_user),
    db: Session = Depends(get_db)
):
    if current_user.role != "superadmin":
        raise HTTPException(status_code=403, detail="Faqat superadmin yangi admin qo'shishi mumkin")

    existing_user = db.query(User).filter(User.username == username).first()
    if existing_user:
        raise HTTPException(status_code=400, detail="Bu username allaqachon mavjud")

    new_admin = User(
        username=username,
        password=password,  # Real loyihada parolni hashlash kerak!
        role="admin",
        branch=branch
    )
    db.add(new_admin)
    db.commit()
    return {"message": f"Yangi admin qo'shildi: {username}"}