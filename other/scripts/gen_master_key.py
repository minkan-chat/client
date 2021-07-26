import hashlib
import base64


dk = hashlib.pbkdf2_hmac('sha256', b'qwerty', b'erik', 100_000)
print(base64.b64encode(dk))