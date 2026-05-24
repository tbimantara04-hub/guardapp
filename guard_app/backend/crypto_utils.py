import base64
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.fernet import Fernet
import os

class HybridCrypto:
    def __init__(self, private_key_path):
        with open(private_key_path, "rb") as key_file:
            self.private_key = serialization.load_pem_private_key(
                key_file.read(),
                password=None,
            )

    def decrypt_symmetric_key(self, encrypted_key_b64):
        """Decrypt the AES (Fernet) key using RSA private key."""
        encrypted_key = base64.b64decode(encrypted_key_b64)
        symmetric_key = self.private_key.decrypt(
            encrypted_key,
            padding.OAEP(
                mgf=padding.MGF1(algorithm=hashes.SHA256()),
                algorithm=hashes.SHA256(),
                label=None
            )
        )
        return symmetric_key

    def decrypt_data(self, encrypted_data_b64, symmetric_key):
        """Decrypt the data using the decrypted Fernet key."""
        f = Fernet(symmetric_key)
        decrypted_data = f.decrypt(encrypted_data_b64)
        return decrypted_data.decode('utf-8')

    def hybrid_decrypt(self, encrypted_data_b64, encrypted_key_b64):
        """Perform full hybrid decryption."""
        sym_key = self.decrypt_symmetric_key(encrypted_key_b64)
        decrypted_text = self.decrypt_data(encrypted_data_b64, sym_key)
        return decrypted_text

    def decrypt_rsa(self, encrypted_data_b64):
        """Decrypt data encrypted purely with RSA."""
        encrypted_data = base64.b64decode(encrypted_data_b64)
        decrypted_data = self.private_key.decrypt(
            encrypted_data,
            padding.OAEP(
                mgf=padding.MGF1(algorithm=hashes.SHA256()),
                algorithm=hashes.SHA256(),
                label=None
            )
        )
        return decrypted_data.decode('utf-8')
