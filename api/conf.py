import base64

PORT = 4000

MONGODB_HOST = {
    'host': 'localhost',
    'port': 27017
}

MONGODB_DBNAME = 'cyberStudents'

WORKERS = 32

# 256-bit AES key for encryption/decryption
AES_KEY = base64.b64decode("w3hJgrAY8K8bZ7xJtcHq2jxFdED0Gr97xgE0f4Iv3Ak=")
