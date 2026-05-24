import os
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives import serialization

def generate_keys():
    print("Generating RSA Key Pair for the Server...")
    private_key = rsa.generate_private_key(
        public_exponent=65537,
        key_size=2048,
    )

    private_pem = private_key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.NoEncryption()
    )

    public_key = private_key.public_key()
    public_pem = public_key.public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo
    )

    keys_dir = os.path.join(os.path.dirname(__file__), 'keys')
    os.makedirs(keys_dir, exist_ok=True)

    with open(os.path.join(keys_dir, 'server_private.pem'), 'wb') as f:
        f.write(private_pem)

    with open(os.path.join(keys_dir, 'server_public.pem'), 'wb') as f:
        f.write(public_pem)

    print(f"Keys successfully generated in {keys_dir}")

if __name__ == "__main__":
    generate_keys()
