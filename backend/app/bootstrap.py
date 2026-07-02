from app.database import Base, SessionLocal, engine
from app.seed import seed_demo_data


def main() -> None:
    Base.metadata.create_all(bind=engine)
    db = SessionLocal()
    try:
        seed_demo_data(db)
    finally:
        db.close()
    print("SurfaceWatch database initialized with demo data.")


if __name__ == "__main__":
    main()
