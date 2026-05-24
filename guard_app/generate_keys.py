import os
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives import serialization

def generate_keys():
    # Generate private key
    private_key = rsa.generate_private_key(
        public_exponent=65537,
        key_size=2048,
    )

    # Serialize private key
    private_pem = private_key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.NoEncryption()
    )

    # Generate public key
    public_key = private_key.public_key()

    # Serialize public key
    public_pem = public_key.public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo
    )

    # Save keys
    keys_dir = 'backend/keys'
    if not os.path.exists(keys_dir):
        os.makedirs(keys_dir)

    with open(os.path.join(keys_dir, 'server_private.pem'), 'wb') as f:
        f.write(private_pem)

    with open(os.path.join(keys_dir, 'server_public.pem'), 'wb') as f:
        f.write(public_pem)

    print("Keys generated successfully in backend/keys/")

if __name__ == "__main__":
    generate_keys()
