from datetime import datetime, timedelta
from time import mktime
from tornado.escape import json_decode, utf8
from tornado.gen import coroutine
from uuid import uuid4
import hashlib  ### hash libarary to hash email for lookup instead of encrypting email.

### Add the needed packages for encryption and hasing

from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.backends import default_backend
import os
import base64

### Adding Functions for Hashing and Verifying Passwords
### Salt is randomly generated for each password to avoid identical hashes for common passwrod. Salt is stored for each user password

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

def verify_password(stored_hash: str, stored_salt: str, input_password: str) -> bool:
    salt = base64.b64decode(stored_salt)
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=32,
        salt=salt,
        iterations=100_000,
        backend=default_backend()
    )
    try:
        kdf.verify(input_password.encode(), base64.b64decode(stored_hash))
        return True
    except Exception:
        return False

def hash_email(email: str) -> str:  ### hashing email and storing it for lookup.
    return hashlib.sha256(email.encode()).hexdigest()

from .base import BaseHandler

class LoginHandler(BaseHandler):

    @coroutine
    def generate_token(self, email):
        token_uuid = uuid4().hex
        expires_in = datetime.now() + timedelta(hours=2)
        expires_in = mktime(expires_in.utctimetuple())

        user = yield self.db.users.find_one({
            'email_hash': hash_email(email)
        }, {
            'tag_name': 1
        })

        token = {
            'token': token_uuid,
            'expiresIn': expires_in,
            'tag_name': user.get('tag_name', '') ### Tag_Name is for tracking purposes for this project.
        }

        yield self.db.users.update_one({
            'email_hash': hash_email(email) ### handler is looking for hashed_email
        }, {
            '$set': token
        })

        return token

    @coroutine
    def post(self):
        try:
            body = json_decode(self.request.body)
            email = body['email'].lower().strip()
            if not isinstance(email, str):
                raise Exception()
            password = body['password']
            if not isinstance(password, str):
                raise Exception()
        except:
            self.send_error(400, message='You must provide an email address and password!')
            return

        if not email:
            self.send_error(400, message='The email address is invalid!')
            return

        if not password:
            self.send_error(400, message='The password is invalid!')
            return

        user = yield self.db.users.find_one({
          'email_hash': hash_email(email) ### hashed email
        }, {
          'password_hash': 1, ### Passowrd is removed and replaced by Hash
          'password_salt': 1,  ### Passowrd is removed and replaced by Salt
          'tag_name': 1 ### adding this field just for tracking purposes in the project.
        })

        if user is None:
            self.send_error(403, message='The email address and password are invalid!')
            return
        
        ### Verifying Password Hash and Salt instead of the actual passowrd.

        if not verify_password(user['password_hash'], user['password_salt'], password):
            self.send_error(403, message='The email address and password are invalid!')
            return

        token = yield self.generate_token(email)

        self.set_status(200)
        self.response['token'] = token['token']
        self.response['expiresIn'] = token['expiresIn']

        self.write_json()
