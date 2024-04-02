import logging
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives import padding
from cryptography.hazmat.backends import default_backend
import os
from typing import Union, Tuple
import timeit

def load_encryption_key(filename: str = "encryption_key.key") -> bytes:
    """
    Loads the encryption key from the given file.
    """
    with open(filename, "rb") as key_file:
        return key_file.read()
    
def load_iv(filename: str = "encryption_iv.iv") -> bytes:
    """
    Loads the IV from the given file.
    """
    with open(filename, "rb") as iv_file:
        return iv_file.read()

# Load the AES key from the file
encryption_key = load_encryption_key()
# Generate IV once 
iv = load_iv()


def encrypt(payload: bytes, key: bytes, cipher=algorithms.AES, mode=modes.CBC) -> Tuple[bytes, bytes]:
    """
    Encrypts the given payload using the specified cipher and mode.

    - payload: The data to be encrypted.
    - key: The encryption key.
    - cipher: The encryption cipher (default: AES).
    - mode: The encryption mode (default: CBC).
    """

    try:
       
        cipher_instance = Cipher(cipher(key), mode(iv), backend=default_backend())
        encryptor = cipher_instance.encryptor()

        padder = padding.PKCS7(cipher.block_size).padder()
        padded_payload = padder.update(payload) + padder.finalize()

        encrypted_chunks = [encryptor.update(chunk) for chunk in chunks(padded_payload, cipher.block_size)]
        encrypted_payload = b''.join(encrypted_chunks) + encryptor.finalize()
        #print("iv in encrypt",iv)
        #print("key is ", encryption_key)

        return encrypted_payload, iv
    except Exception as e:
        logging.error(f"Encryption failed: {str(e)}")
        raise ValueError("Encryption failed: An error occurred during encryption.")



def decrypt(packet: bytes, IV: bytes, key: bytes, cipher=algorithms.AES, mode=modes.CBC) -> bytes:
    """
    Decrypts the given packet using the specified cipher and mode.

    - packet: The encrypted data (without IV).
    - iv: The initialization vector (IV).
    - key: The decryption key.
    - cipher: The decryption cipher (default: AES).
    - mode: The decryption mode (default: CBC).
    """
    #print(encryption_key, "encryption key in decrypt", len(encryption_key))
    #print("iv in decrypt", len(iv), iv)
    if len(iv) != 16:
        raise ValueError(f"Invalid IV length {len(iv)}, must be 16 bytes")
    try:
        cipher_instance = Cipher(cipher(key), mode(iv), backend=default_backend())
        decryptor = cipher_instance.decryptor()

        decrypted_payload = decryptor.update(packet) + decryptor.finalize()

        unpadder = padding.PKCS7(cipher.block_size).unpadder()
        unpadded_payload = unpadder.update(decrypted_payload) + unpadder.finalize()

        return unpadded_payload
    except ValueError as e:
        if "Invalid padding" in str(e):
            raise ValueError("Decryption failed: Invalid padding")
        else:
            raise ValueError("Decryption failed: An error occurred during decryption.")



def chunks(data: bytes, size: int) -> bytes:
    """
    Splits the given data into chunks of the specified size.
    """
    for i in range(0, len(data), size):
        yield data[i:i + size]

def benchmark_performance():
    """
    Benchmarks the performance impact for different packet sizes.
    """
    packet_sizes = [1024, 2048, 4096, 8192]
    num_iterations = 1000  # Number of iterations for each test
    for size in packet_sizes:
        payload = os.urandom(size)

        encrypted_payload, _ = encrypt(payload, encryption_key, cipher=algorithms.AES, mode=modes.CBC)

        encryption_time = timeit.timeit(lambda: encrypt(payload, encryption_key, cipher=algorithms.AES, mode=modes.CBC), number=num_iterations)
        decryption_time = timeit.timeit(lambda: decrypt(encrypted_payload, iv, encryption_key, cipher=algorithms.AES, mode=modes.CBC), number=num_iterations)

        print(f"Packet Size: {size} bytes")
        print(f"Avg Encryption Time: {encryption_time / num_iterations:.6f} seconds")
        print(f"Avg Decryption Time: {decryption_time / num_iterations:.6f} seconds")
        print("")

if __name__ == "__main__":
    benchmark_performance()
