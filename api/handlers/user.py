from tornado.web import authenticated

### Adding the needed packages for decrypting process

from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend
import base64
from api.conf import AES_KEY

### decrypting display_name function defined

def decrypt_display_name(data):
    iv = base64.b64decode(data['iv'])
    tag = base64.b64decode(data['tag'])
    ciphertext = base64.b64decode(data['ciphertext'])

    decryptor = Cipher(
        algorithms.AES(AES_KEY),
        modes.GCM(iv, tag),
        backend=default_backend()
    ).decryptor()

    return decryptor.update(ciphertext) + decryptor.finalize()

from .auth import AuthHandler

class UserHandler(AuthHandler):

    @authenticated
    def get(self):
     
        self.set_status(200)
        self.response['email'] = self.current_user['email']

        ### Adding the function to decrypt the display_name
        
        self.response['displayName'] = self.current_user['display_name']
        self.write_json()
