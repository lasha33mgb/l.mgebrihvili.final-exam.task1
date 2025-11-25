# Step 1: Generate RSA Key Pair for User A
# This will create a public and private key for encrypting/decrypting

from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives import serialization

# I want to generate a key pair (private + public)
user_a_private_key = rsa.generate_private_key(
    public_exponent=65537,  # common public exponent
    key_size=2048  # this means strong security, but not too slow
)

# Now I save the private key
with open("user_a_private_key.pem", "wb") as f:
    f.write(user_a_private_key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,  # standard format
        encryption_algorithm=serialization.NoEncryption()  # no password
    ))

# Then I get the public key from the private one
user_a_public_key = user_a_private_key.public_key()

# And save the public key too
with open("user_a_public_key.pem", "wb") as f:
    f.write(user_a_public_key.public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo
    ))

print("✔️ RSA keys for User A created and saved.")







# Step 2: User B encrypts a secret message using AES-256
# Then encrypts the AES key using User A's RSA public key

from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.hazmat.primitives import hashes
import os

# 1. Let's create a secret message and save it to message.txt
message = b"This is a top secret message for User A."
with open("message.txt", "wb") as f:
    f.write(message)

# 2. Generate a random AES key (32 bytes = 256 bits) and a random IV (initialization vector)
aes_key = os.urandom(32)  # AES-256 key
iv = os.urandom(16)       # 16 bytes IV for CBC mode

# 3. Encrypt the message using AES (CBC mode)
cipher = Cipher(algorithms.AES(aes_key), modes.CBC(iv))
encryptor = cipher.encryptor()

# We need to make the message a multiple of 16 bytes for AES CBC
padding_length = 16 - (len(message) % 16)
padded_message = message + bytes([padding_length]) * padding_length

encrypted_message = encryptor.update(padded_message) + encryptor.finalize()

# Save the encrypted message
with open("encrypted_message.bin", "wb") as f:
    f.write(iv + encrypted_message)  # we save IV + ciphertext together

# 4. Load User A's public key to encrypt the AES key
with open("user_a_public_key.pem", "rb") as f:
    public_key = serialization.load_pem_public_key(f.read())

# Encrypt the AES key using RSA
encrypted_aes_key = public_key.encrypt(
    aes_key,
    padding.OAEP(
        mgf=padding.MGF1(algorithm=hashes.SHA256()),
        algorithm=hashes.SHA256(),
        label=None
    )
)

# Save the encrypted AES key
with open("aes_key_encrypted.bin", "wb") as f:
    f.write(encrypted_aes_key)

print("✔️ Message encrypted with AES and AES key encrypted with RSA.")






# Step 3: User A decrypts the AES key with their RSA private key
# Then uses it to decrypt the encrypted message

from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.hazmat.primitives import hashes

# 1. Load User A's private RSA key
with open("user_a_private_key.pem", "rb") as f:
    private_key = serialization.load_pem_private_key(f.read(), password=None)

# 2. Read the encrypted AES key and decrypt it using RSA
with open("aes_key_encrypted.bin", "rb") as f:
    encrypted_aes_key = f.read()

aes_key = private_key.decrypt(
    encrypted_aes_key,
    padding.OAEP(
        mgf=padding.MGF1(algorithm=hashes.SHA256()),
        algorithm=hashes.SHA256(),
        label=None
    )
)

# 3. Read the encrypted message (first 16 bytes = IV, rest = ciphertext)
with open("encrypted_message.bin", "rb") as f:
    iv_ciphertext = f.read()
    iv = iv_ciphertext[:16]
    encrypted_message = iv_ciphertext[16:]

# 4. Decrypt the message using AES
cipher = Cipher(algorithms.AES(aes_key), modes.CBC(iv))
decryptor = cipher.decryptor()
decrypted_padded = decryptor.update(encrypted_message) + decryptor.finalize()

# Remove padding
padding_length = decrypted_padded[-1]
decrypted_message = decrypted_padded[:-padding_length]

# Save the decrypted message
with open("decrypted_message.txt", "wb") as f:
    f.write(decrypted_message)

print("✔️ AES key and message successfully decrypted by User A.")