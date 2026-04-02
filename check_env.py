# check_env.py
import os
from dotenv import load_dotenv

print("--- Starting environment check ---")

try:
    # Try to load the .env file
    found_file = load_dotenv()
    
    if not found_file:
        print("ERROR: Did not find a .env file in this folder.")
        print("Please check the file is named exactly '.env' (not .env.txt)")
    else:
        print("SUCCESS: Found the .env file!")
    
    # Now, let's try to read the variables
    db_host = os.environ.get('DB_HOST')
    db_user = os.environ.get('DB_USER')
    db_pass = os.environ.get('DB_PASS')
    db_name = os.environ.get('DB_NAME')

    if db_pass is None:
        masked_db_pass = None
    elif db_pass == "":
        masked_db_pass = "(empty)"
    else:
        masked_db_pass = "*" * 8

    print(f"DB_HOST = {db_host}")
    print(f"DB_USER = {db_user}")
    print(f"DB_PASS = {masked_db_pass}")
    print(f"DB_NAME = {db_name}")

    if not all([db_host, db_user, db_name]):
        print("\nWARNING: One or more variables are missing from your .env file.")
    else:
        print("\nSUCCESS: All required variables are present.")

except ImportError:
    print("\nCRITICAL ERROR: The 'python-dotenv' library is not installed.")
    print("Please run this command: pip install python-dotenv")
except Exception as e:
    print(f"\nAn unexpected error happened: {e}")

print("--- Check complete ---")