from passwordChecker import PasswordChecker
from pymongo import MongoClient
from cryptography.fernet import Fernet
import os
from dotenv import load_dotenv

# loadind environment variables for development
load_dotenv(".env.dev")

# Driver function
def main():
    
    # Create an instance of PasswordChecker with default rules
    checker = PasswordChecker()
    
    # set up mongodb connection for password storage
    # Create connection to MongoDB server
    mongo_uri = os.getenv("MONGO_URI")
    if not mongo_uri:
        raise ValueError("MongoDB URI not found in environment variables.")
    
    # Create client object
    mongodb_client = MongoClient(mongo_uri)
    
    # Create client mongodb database
    db = mongodb_client["password_manager"]
    
    # Create password collection to collect all the password documents
    collection = db["passwords"]
    
    # get an encryption key
    key = checker.generate_encryption_key()

    # Get username from user
    username = input("Enter your username: ")

    # get, Check, and store user's password.
    while True:
        # Get password from user
        password = checker.get_user_password()
        
        # validate password
        is_password_validated =  checker.password_pass_validation_process(username, password, key, collection)

        # Storing the password in the vault
        if is_password_validated:
            checker.store_password_in_vault(username, password, collection, key)
            break 
        
# Running the module
if __name__ == "__main__":
    main()