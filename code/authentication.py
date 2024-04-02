from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.hazmat.primitives.asymmetric import rsa
import cryptography.exceptions
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import serialization


# Load private key from file
with open("private_key.pem", "rb") as key_file:
    private_key = serialization.load_pem_private_key(
        key_file.read(),
        password=None,
        backend=default_backend()
    )

# Load public key from file
with open("public_key.pem", "rb") as key_file:
    public_key = serialization.load_pem_public_key(
        key_file.read(),
        backend=default_backend()
    )

class DigitalSignature:
    def __init__(self, private_key, public_key):
        """
        Initialize the DigitalSignature instance.
        Args:
            private_key (cryptography.hazmat.backends.openssl.rsa._RSAPrivateKey): Private key object.
            public_key (cryptography.hazmat.backends.openssl.rsa._RSAPublicKey): Public key object.
        """
        self.private_key = private_key
        self.public_key = public_key
   
    def sign_packet(self, packet):
        """
        Signs a packet using the private key.
        Args:
            packet (bytes): The data packet to be signed.
        Returns:
            bytes: The signature of the packet.
        """
        if not isinstance(self.private_key, rsa.RSAPrivateKey):
            raise ValueError("Invalid private key")
        signature = self.private_key.sign(
            packet,
            padding.PSS(
                mgf=padding.MGF1(hashes.SHA256()), salt_length=padding.PSS.MAX_LENGTH
            ),
            hashes.SHA256(),
        )
        #print("---------->>>>>>>>>>>>>>>>>>><<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<")
        #print("signature from authentication file:-",signature)
        #print("")
        #print("printing signed packet ", packet)
        #print("---------->>>>>>>>>>>>>>>>>>><<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<")

        return signature
    
    def verify_packet(self, packet, signature):
        #print("---------->>>>>>>>>>>>>>>>>>><<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<")
        #print("printing header bytes which is original packet ", packet)
        #print("")
        #print("printing signature in verifying file", signature)
        #print("---------->>>>>>>>>>>>>>>>>>><<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<")

        """
        Verifies the signature of a packet using the public key.
        Args:
            packet (bytes): The data packet to be verified.
            signature (bytes): The signature of the packet.
        Returns:
            bool: True if the signature is valid, False otherwise.
        """
        if not isinstance(self.public_key, rsa.RSAPublicKey):
            raise ValueError("Invalid public key")
        try:
            self.public_key.verify(
                signature,
                packet,
                padding.PSS(
                    mgf=padding.MGF1(hashes.SHA256()), salt_length=padding.PSS.MAX_LENGTH
                ),
                hashes.SHA256(),
            )
            return True
        except cryptography.exceptions.InvalidSignature:
            return False

def main():
    # Create a DigitalSignature instance with the generated keys
    signature = DigitalSignature(private_key, public_key)

    # Example usage:
    packet = b"Hello, this is the data to be signed."
    signature_value = signature.sign_packet(packet)
    print("Packet Signature:", signature_value)

    is_valid = signature.verify_packet(packet, signature_value)
    print("Signature Valid:", is_valid)

if __name__ == "__main__":
    main()
