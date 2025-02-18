# create_superadmin.py
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker
from main import User, Base  # main.py dan User modelini import qilamiz

# Ma'lumotlar bazasiga ulanish
DATABASE_URL = "sqlite:///./test.db"
engine = create_engine(DATABASE_URL, connect_args={"check_same_thread": False})
SessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=engine)

# Ma'lumotlar bazasini yaratish
Base.metadata.create_all(bind=engine)

def create_superadmin():
    db = SessionLocal()
    try:
        # Avval superadmin mavjudligini tekshirish
        existing_superadmin = db.query(User).filter(User.role == "superadmin").first()
        if existing_superadmin:
            print("SuperAdmin allaqachon mavjud!")
            return

        # Yangi SuperAdmin yaratish
        superadmin = User(
            username="superadmin",
            password="superadmin1",  # Bu yerga xavfsiz parol qo'ying
            role="superadmin",
            branch=None,  # SuperAdmin uchun branch shart emas
            group_name=None  # SuperAdmin uchun guruh shart emas
        )
        
        db.add(superadmin)
        db.commit()
        print("SuperAdmin muvaffaqiyatli yaratildi!")
        print("Username: superadmin")
        print("Password: your-secure-password")
        
    except Exception as e:
        print(f"Xatolik yuz berdi: {str(e)}")
        db.rollback()
    finally:
        db.close()

if __name__ == "__main__":
    create_superadmin()