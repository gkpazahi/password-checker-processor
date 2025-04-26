"""Module to get user's username and password to be stored as document in mondb database.
   Before storage in the environment variables, the password pass a 4 steps validation process
   and encrypted ."""
import hashlib
import pymongo.collection
import requests
import datetime
from cryptography.fernet import Fernet
import pymongo
import os
from dotenv import load_dotenv
import logging

# Load environment variables from .env
load_dotenv(".env.dev")

# Configure logging
logging.basicConfig(level=logging.INFO, format="%(asctime)s - %(levelname)s - %(message)s")

# PasswordChecker class 
class PasswordChecker:
    # Constructor
    def __init__(
        self,
        min_length: int = 8,
        require_uppercase: bool = True,
        require_lowercase: bool = True,
        require_digit: bool = True,
        require_special: bool = True,
    ):
        self.min_length = min_length
        self.require_uppercase = require_uppercase
        self.require_lowercase = require_lowercase
        self.require_digit = require_digit
        self.require_special = require_special

    # Prompts user to provide its username
    def get_password_duration(self) -> datetime.timedelta:
        """Get password expiry duration from the user."""
        try:
            duration = int(input("How many days should the password last? "))
            if duration <= 0:
                raise ValueError("Duration must be a positive integer.")
            return datetime.timedelta(days=duration)
        except ValueError as e:
            logging.error(f"Invalid input for password duration: {e}")
            
    # generate encryption key
    def generate_encryption_key(self) -> str:
        """Generate or retrieve an encryption key."""
        encryption_key = os.getenv("ENCRYPTION_KEY")
        if not encryption_key:
            encryption_key = Fernet.generate_key().decode()
            # Optionally, save the new key to the environment or a file for future use
            os.environ["ENCRYPTION_KEY"] = encryption_key
            logging.warning("No encryption key found in environment variables. Generate and save a new key.")
        logging.info("Encryption key retrieved successfully.")
        #return Fernet(encryption_key.encode())
        return encryption_key

    def get_user_password(self) -> str:
        """Get password input from the user."""
        return input("Enter your new password: ")

    def is_valid(self, password: str) -> tuple[bool, str]:
        """Check if the password meets the requirements."""
        if len(password) < self.min_length:
            return False, f"Password must be at least {self.min_length} characters long."

        if self.require_uppercase and not any(char.isupper() for char in password):
            return False, "Password must contain at least one uppercase letter."

        if self.require_lowercase and not any(char.islower() for char in password):
            return False, "Password must contain at least one lowercase letter."

        if self.require_digit and not any(char.isdigit() for char in password):
            return False, "Password must contain at least one digit."

        if self.require_special and not any(not char.isalnum() for char in password):
            return False, "Password must contain at least one special character."

        return True, "Password is valid."

    def is_compromised(self, password: str) -> tuple[bool, str]:
        """Check if the password has been compromised using HIBP API."""
        try:
            sha1_password = hashlib.sha1(password.encode("utf-8")).hexdigest().upper()
            prefix, suffix = sha1_password[:5], sha1_password[5:]

            url = f"https://api.pwnedpasswords.com/range/{prefix}"
            response = requests.get(url)

            if response.status_code != 200:
                raise RuntimeError("Failed to fetch data from HIBP API.")

            for line in response.text.splitlines():
                h, count = line.split(":")
                if h == suffix:
                    return True, f"This password has been compromised {count} times."

            return False, "This password is safe and has not been compromised."
        except Exception as e:
            logging.error(f"Error checking password compromised: {e}")
            return False, f"Error checking password compromised: {e}"

    # Check if password is expired
    def is_password_expired(self, username: str, collection: pymongo.collection.Collection) -> tuple[bool, str]:
        """
        Check if the password for the given username has expired.

        Args:
            username (str): The username to check.
            collection (pymongo.collection.Collection): The MongoDB collection containing user data.

        Returns:
            Tuple[bool, str]: A tuple containing a boolean indicating if the password is expired,
                            and a string with a message (either the expiration status or an error message).
        """
        try:
            # Query the database for the specific user's data
            user_data = collection.find_one({"username": username}, {"expiration_date": 1})
            
            if not user_data:
                return False, f"No user found with username: {username}."

            # Check if the expiration_date field exists in the user data
            if "expiration_date" not in user_data:
                return False, "No expiration date found for this user."

            expiration_date = user_data["expiration_date"]
            current_time = datetime.datetime.now()

            # Compare the current time with the expiration date
            if current_time > expiration_date:
                return True, "Password has expired."
            else:
                return False, f"Password is still valid. Expires on {expiration_date}."

        except pymongo.errors.PyMongoError as e:
            # Log MongoDB-specific errors
            logging.error(f"MongoDB error while checking password expiry for user {username}: {e}")
            return True, f"Database error occurred while checking password expiry."

        except Exception as e:
            # Log any other unexpected errors
            logging.error(f"Unexpected error while checking password expiry for user {username}: {e}")
            return True, f"An unexpected error occurred while checking password expiry."
    
    # Check if password is already used     
    def is_already_used(self, password: str, key: Fernet, collection: pymongo.collection.Collection) -> tuple[bool, str]:
        """
        Check if the password has already been used by any user in the system.

        Args:
            password (str): The password to verify.
            key (Fernet): The Fernet key for decrypting stored passwords.
            collection (pymongo.collection.Collection): The MongoDB collection containing user data.

        Returns:
            Tuple[bool, str]: A tuple containing a boolean indicating if the password has been used before,
                            and a string with a message (either the usage status or an error message).
        """
        try:
            # Retrieve all user records from the collection
            user_data = collection.find({}, {"encrypted_password": 1})
            
            if not user_data:
                return False, "No user data found in the collection."

            # Iterate through all user records and check their encrypted passwords
            for record in user_data:
                try:
                    # Decrypt the stored password and compare it with the provided password
                    decrypted_password = Fernet(key).decrypt(record["encrypted_password"]).decode("utf-8")
                    if decrypted_password == password:
                        return True, "Password is already used."
                except Exception as decryption_error:
                    # Log decryption errors but continue checking other records
                    logging.error(f"Error decrypting password for record {record.get('_id')}: {decryption_error}")
                    continue

            # If no match is found, the password has not been used before
            return False, "Password has not been used before."

        except pymongo.errors.PyMongoError as e:
            # Log MongoDB-specific errors
            logging.error(f"MongoDB error while checking password history: {e}")
            return False, f"Database error occurred while checking password history."

        except Exception as e:
            # Log any other unexpected errors
            logging.error(f"Unexpected error while checking password history: {e}")
            return False, f"An unexpected error occurred while checking password history."
    
    # password Validation processes
    def password_pass_validation_process(
        self, username: str, password: str, key: Fernet, collection: pymongo.collection.Collection) -> bool:
        """Validate the password through all checks."""
        valid, message = self.is_valid(password)
        if not valid:
            logging.warning(message)
            return False

        compromised, message = self.is_compromised(password)
        if compromised:
            logging.warning(message)
            return False

        used, message = self.is_already_used(password, key, collection)
        if used:
            logging.warning(message)
            return False

        expired, message = self.is_password_expired(username, collection)
        if expired:
            logging.warning(message)
            return False

        return True

    def store_password_in_vault(
        self, username: str, password: str, collection: pymongo.collection.Collection, key: Fernet
    ) -> None:
        """Store the password securely in the vault after validation."""
        try:
            # Encrypt the password
            encrypted_password = Fernet(key).encrypt(password.encode("utf-8"))

            # Get the current date and time
            creation_date = datetime.datetime.now()

            # Get the password duration
            password_duration = self.get_password_duration()

            # Determine the password expiration date
            expiration_date = creation_date + password_duration

            # Store the encrypted password and metadata in MongoDB
            collection.insert_one(
                {
                    "username": username,
                    "encrypted_password": encrypted_password,
                    "creation_date": creation_date,
                    "expiration_date": expiration_date
                }
            )
            logging.info("Password stored securely in the vault.")
        except Exception as e:
            logging.error(f"Error storing password: {e}")
    ### End clss PasswordChecker ###