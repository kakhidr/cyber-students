from json import dumps
from logging import info
from tornado.escape import json_decode, utf8
from tornado.gen import coroutine

import hashlib

### Add the needed packages for and hasing

from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.backends import default_backend
import os
import base64

### Add the needed packages for encrypting

from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from api.conf import AES_KEY

from .base import BaseHandler

### Helper function to hash passwords

def hash_password(password: str, salt: bytes = None) -> dict:
    if salt is None:
        salt = os.urandom(16)
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=32,
        salt=salt,
        iterations=100_000,
        backend=default_backend()
    )
    key = kdf.derive(password.encode())
    return {
        'salt': base64.b64encode(salt).decode(),
        'hash': base64.b64encode(key).decode()
    }

def hash_email(email: str) -> str:    ### hash email function
    return hashlib.sha256(email.encode()).hexdigest()

### Helper function to encrypt fields (PII)

def encrypt_field(plaintext: str) -> dict:
    iv = os.urandom(12)
    encryptor = Cipher(
        algorithms.AES(AES_KEY),
        modes.GCM(iv),
        backend=default_backend()
    ).encryptor()

    ciphertext = encryptor.update(plaintext.encode()) + encryptor.finalize()

    return {
        'iv': base64.b64encode(iv).decode(),
        'tag': base64.b64encode(encryptor.tag).decode(),
        'ciphertext': base64.b64encode(ciphertext).decode()
    }

class RegistrationHandler(BaseHandler):

    @coroutine
    def post(self):
        try:
            body = json_decode(self.request.body)
            email = body['email'].lower().strip()
            print("Normalized email:", email) ### normalizing emails to avoid sensitive cases.
            if not isinstance(email, str):
                raise Exception()
            email_hash = hash_email(email) ### hashing email and storing it for lookup.
            print("Email hash:", email_hash) ### debug line
            password = body['password']
            if not isinstance(password, str):
                raise Exception()
            display_name = body.get('displayName')
            if display_name is None:
                display_name = email
            if not isinstance(display_name, str):
                raise Exception()
            tag_name = display_name  ### Plain text tracking tag
            address = body.get('address')            ### Verifying PII fields
            dob = body.get('dob')                    ### Verifying PII Fields
            phone = body.get('phone')                ### Verifying PII Fields
            disabilities = body.get('disabilities')  ### Verifying PII Fields

            if not all(isinstance(field, str) for field in [address, dob, phone]) or not isinstance(disabilities, list):
                self.send_error(400, message='Invalid or missing personal details!')
                return
        except Exception as e:
            self.send_error(400, message='You must provide an email address, password and display name!')
            return

        if not email:
            self.send_error(400, message='The email address is invalid!')
            return

        if not password:
            self.send_error(400, message='The password is invalid!')
            return

        if not display_name:
            self.send_error(400, message='The display name is invalid!')
            return

        user = yield self.db.users.find_one({
          'email_hash': email_hash
        }, {})

        if user is not None:
            print("User with this email already exists.") ### verify user already exists in DB.
            self.send_error(409, message='A user with the given email address already exists!')
            return
        else:
            print("No existing user found. Proceeding to register.") ### User is not registered.
        
        ### Hash Password is used instead of plain password
        
        credentials = hash_password(password)

        encrypted_email = encrypt_field(email)
        encrypted_display_name = encrypt_field(display_name)
        encrypted_address = encrypt_field(address)
        encrypted_dob = encrypt_field(dob)
        encrypted_phone = encrypt_field(phone)
        encrypted_disabilities = encrypt_field(','.join(disabilities))

        ### Encrypting PII for users to store in DB

        # print("Encrypted email:", encrypted_email)
        # print("Encrypted display_name:", encrypted_display_name)
        # print("Encrypted address:", encrypted_address)
        # print("Encrypted dob:", encrypted_dob)
        # print("Encrypted phone:", encrypted_phone)
        # print("Encrypted disabilities:", encrypted_disabilities)


        ### Saving encrypted PII for users to store in DB

        yield self.db.users.insert_one({
            'email_hash': email_hash,
            'email': encrypted_email,
            'password_hash': credentials['hash'],
            'password_salt': credentials['salt'],
            'tag_name': tag_name, ### this is only for the project, for tracking purposes.
            'display_name': encrypted_display_name,
            'address': encrypted_address,
            'dob': encrypted_dob,
            'phone': encrypted_phone,
            'disabilities': encrypted_disabilities
        })

        self.set_status(200)
        self.response['message'] = "User registered successfully."
        self.write_json()
