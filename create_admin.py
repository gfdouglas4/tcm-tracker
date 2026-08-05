"""
Run inside the app container to create the first admin user:

    docker compose exec app python create_admin.py <username>

Prints a temporary password. The admin must set up 2FA on first login.
"""
import sys
import secrets

from app.database import Base, engine, SessionLocal
from app import models, auth

Base.metadata.create_all(bind=engine)


def main():
    if len(sys.argv) != 2:
        print("Usage: python create_admin.py <username>")
        sys.exit(1)

    username = sys.argv[1].strip().lower()
    db = SessionLocal()
    try:
        existing = db.query(models.User).filter(models.User.username == username).first()
        if existing:
            print(f"User '{username}' already exists.")
            sys.exit(1)

        temp_password = secrets.token_urlsafe(9)
        user = models.User(
            username=username,
            password_hash=auth.hash_password(temp_password),
            role=models.UserRole.admin,
            must_change_password=True,
        )
        db.add(user)
        db.commit()
        print(f"Created admin user '{username}'.")
        print(f"Temporary password: {temp_password}")
        print("They will set up 2FA on first login.")
    finally:
        db.close()


if __name__ == "__main__":
    main()
