import os
import psycopg2
import bcrypt
from dotenv import load_dotenv

# Load your database URL from the .env file
load_dotenv()
DATABASE_URL = os.getenv("DATABASE_URL")

def create_super_admin():
    conn = psycopg2.connect(DATABASE_URL)
    cursor = conn.cursor()
    
    # Credentials for your new Super Admin
    username = "HQ_Admin"
    password = "securepassword123"  # Change this to whatever you want
    assigned_city = "Global Command"
    role = "super_admin"
    
    # Hash the password exactly how the Flask app expects it
    salt = bcrypt.gensalt()
    hashed_password = bcrypt.hashpw(password.encode('utf-8'), salt).decode('utf-8')
    
    try:
        cursor.execute(
            "INSERT INTO admins (username, password_hash, assigned_city, role) VALUES (%s, %s, %s, %s)",
            (username, hashed_password, assigned_city, role)
        )
        conn.commit()
        print(f"✅ Recovery successful! You can now log into the Admin Portal as '{username}'.")
    except Exception as e:
        print(f"❌ Error inserting admin: {e}")
    finally:
        cursor.close()
        conn.close()

if __name__ == "__main__":
    create_super_admin()