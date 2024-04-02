from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import rsa
import os

# RSA key generation
private_key = rsa.generate_private_key(
    public_exponent=65537,
    key_size=2048,
    backend=default_backend()
)
public_key = private_key.public_key()

# Save private key
with open("private_key.pem", "wb") as private_file:
    private_file.write(private_key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.TraditionalOpenSSL,
        encryption_algorithm=serialization.NoEncryption()
    ))

# Save public key
with open("public_key.pem", "wb") as public_file:
    public_file.write(public_key.public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo
    ))

print("RSA keys generated and saved!")

# AES key generation
def generate_random_key(key_length: int = 32) -> bytes:
    return os.urandom(key_length)

encryption_key = generate_random_key()

# Save encryption key
with open("encryption_key.key", "wb") as key_file:
    key_file.write(encryption_key)

print("AES encryption key generated and saved!")

# IV generation
def generate_iv(iv_length: int = 16) -> bytes:
    return os.urandom(iv_length)

iv = generate_iv()

# Save IV
with open("encryption_iv.iv", "wb") as iv_file:
    iv_file.write(iv)

print("Initialization Vector (IV) generated and saved!")

if __name__ == "__main__":
    print("Keys generated!")
