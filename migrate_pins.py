import mysql.connector
import bcrypt
from dotenv import load_dotenv
import os

BCRYPT_PREFIXES = ('$2a$', '$2b$', '$2y$')


def is_bcrypt_hash(value):
    """Returns True when the provided value looks like a bcrypt hash."""
    if not isinstance(value, str):
        return False
    stripped = value.strip()
    return len(stripped) >= 60 and any(stripped.startswith(prefix) for prefix in BCRYPT_PREFIXES)

# Load credentials from .env
load_dotenv()

DB_HOST = os.environ.get('DB_HOST')
DB_USER = os.environ.get('DB_USER')
DB_PASS = os.environ.get('DB_PASS')
DB_NAME = os.environ.get('DB_NAME')

if not all([DB_HOST, DB_USER, DB_NAME]):
    print("Error: DB_HOST, DB_USER, and DB_NAME must be set in your .env file.")
    exit()

db = None # Define db here to be accessible in finally
cursor = None # Define cursor here

try:
    db = mysql.connector.connect(
        host=DB_HOST,
        user=DB_USER,
        password=DB_PASS,
        database=DB_NAME
    )
    cursor = db.cursor()
    print("Connected to database...")

    # First, make the 'pin' column larger to hold the hash
    try:
        cursor.execute("ALTER TABLE users MODIFY pin VARCHAR(60) NOT NULL;")
        print("Altered 'users.pin' column to VARCHAR(60).")
    except mysql.connector.Error as err:
        print(f"Could not alter table (maybe already altered?): {err}")

    # Fetch all users using 'username' instead of 'user_id'
    cursor.execute("SELECT username, pin FROM users;")
    users = cursor.fetchall()

    updated_count = 0

    for username, pin in users:
        # Skip rows that are already bcrypt hashes.
        if is_bcrypt_hash(pin):
            print(f"Skipping user '{username}': PIN already hashed.")
            continue

        # Hash the plaintext PIN
        print(f"Hashing PIN for user '{username}'...")
        plaintext_pin = pin.encode('utf-8')
        hashed_pin = bcrypt.hashpw(plaintext_pin, bcrypt.gensalt())
        
        # Store the hash (as a string), updating by 'username'
        cursor.execute(
            "UPDATE users SET pin = %s WHERE username = %s",
            (hashed_pin.decode('utf-8'), username)
        )
        updated_count += 1

    if updated_count == 0 and len(users) > 0:
         print("\nAll user PINs were already hashed. No changes made.")
    else:
        db.commit()
        print(f"\nMigration complete! {updated_count} user PINs were securely hashed.")
    
except mysql.connector.Error as err:
    print(f"\nDatabase error: {err}")
    if db:
        db.rollback()
except Exception as e:
    print(f"\nAn unexpected error occurred: {e}")
    if db:
        db.rollback()
finally:
    if cursor:
        cursor.close()
    if db and db.is_connected():
        db.close()
        print("Database connection closed.")