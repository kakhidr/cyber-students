from datetime import datetime
from time import mktime
from tornado.gen import coroutine

### adding the needed fucntions for valdiation & Decrypt user context.
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes 
from cryptography.hazmat.backends import default_backend
import base64
from api.conf import AES_KEY

from .base import BaseHandler

### Decrypt function defined

def decrypt_field(data):
    iv = base64.b64decode(data['iv'])
    tag = base64.b64decode(data['tag'])
    ciphertext = base64.b64decode(data['ciphertext'])

    decryptor = Cipher(
        algorithms.AES(AES_KEY),
        modes.GCM(iv, tag),
        backend=default_backend()
    ).decryptor()

    return decryptor.update(ciphertext) + decryptor.finalize()

class AuthHandler(BaseHandler):

    @coroutine
    def prepare(self):
        super(AuthHandler, self).prepare()

        if self.request.method == 'OPTIONS':
            return

        print("Received headers:", self.request.headers)
        try:
            token = self.request.headers.get('X-Token')
            print("Token received from header:", token)
            if not token:
              raise Exception()
        except:
            self.current_user = None
            self.send_error(400, message='You must provide a token!')
            return

        user = yield self.db.users.find_one({
            'token': token
        }, {
            'email': 1,
            'display_name': 1,
            'expiresIn': 1, ### Token Expiration
            'tag_name': 1 ### Tracking parameter
        })

        if user is None:
            self.current_user = None
            self.send_error(403, message='Your token is invalid!')
            return

        current_time = mktime(datetime.now().utctimetuple())
        if current_time > user['expiresIn']:
            self.current_user = None
            self.send_error(403, message='Your token has expired!')
            return

        ### defensive chaeck to ensure both email and displayName exist before attempting decryption.
        
        if 'email' not in user or 'display_name' not in user:
            self.current_user = None
            self.send_error(403, message='User record is missing required fields.')
            return

        self.current_user = {
            'email': decrypt_field(user['email']).decode(),
            'display_name': decrypt_field(user['display_name']).decode(), ### Decryption process.
            'tag_name': user.get('tag_name', '')
        }
