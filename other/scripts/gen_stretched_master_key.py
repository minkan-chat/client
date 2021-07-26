from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives import kdf
from cryptography.hazmat.primitives.kdf.hkdf import HKDFExpand, HKDF
import base64


info1 = b"enc"
info2 = b"mac"
key_material = base64.b64decode("66Nn+bGSnk0QkWtd3vEiLLzrhiCm3SFkurcpcm+L8GA=")


hkdf1 = HKDFExpand(algorithm=hashes.SHA256(), length=32, info=info1)

hkd2 = HKDFExpand(algorithm=hashes.SHA256(), length=32, info=info2)
print(base64.b64encode(hkdf1.derive(key_material) + hkd2.derive(key_material)))
print(
    bytes(
        "fwNcXC46Kssud1nN3ManWAeN5L0990ZVPZZ/BHdun+sTJvwf7bZF6eb37hwk1bYS3gLGPqUkzFQK63o5soQ9sw==".encode(
            "utf-8"
        )
    )
)  # should be fwNcXC46Kssud1nN3ManWAeN5L0990ZVPZZ/BHdun+sTJvwf7bZF6eb37hwk1bYS3gLGPqUkzFQK63o5soQ9sw==
