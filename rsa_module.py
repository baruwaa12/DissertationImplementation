# hybrid_encryption.py

from Crypto.PublicKey import RSA
from Crypto.Cipher import PKCS1_OAEP, AES
from Crypto.Random import get_random_bytes

import time

# RSA functions as before
def rsa_keygen(key_size=2048):
    key = RSA.generate(key_size)
    private_key = key.export_key()
    public_key = key.publickey().export_key()
    return RSA.import_key(public_key), RSA.import_key(private_key)

def rsa_encrypt(data, public_key):
    cipher_rsa = PKCS1_OAEP.new(public_key)
    return cipher_rsa.encrypt(data)

def rsa_decrypt(ciphertext, private_key):
    cipher_rsa = PKCS1_OAEP.new(private_key)
    return cipher_rsa.decrypt(ciphertext)

# AES functions for symmetric encryption
def aes_encrypt(message, key):
    # Use AES in EAX mode for authenticated encryption
    cipher_aes = AES.new(key, AES.MODE_EAX)
    ciphertext, tag = cipher_aes.encrypt_and_digest(message.encode())
    return cipher_aes.nonce, ciphertext, tag

def aes_decrypt(nonce, ciphertext, tag, key):
    cipher_aes = AES.new(key, AES.MODE_EAX, nonce=nonce)
    decrypted_message = cipher_aes.decrypt_and_verify(ciphertext, tag)
    return decrypted_message.decode()

if __name__ == '__main__':
    # Read large message from file
    with open("large_message.txt", "r") as file:
        message = file.read()
    
    print("Original Message Length:", len(message), "characters")
    
    # Generate RSA keys
    start = time.perf_counter()
    rsa_pub, rsa_priv = rsa_keygen(2048)
    rsa_keygen_time = time.perf_counter() - start
    
    # Generate a random AES key (e.g., 256-bit key)
    aes_key = get_random_bytes(32)
    
    # Encrypt the AES key using RSA
    start = time.perf_counter()
    encrypted_aes_key = rsa_encrypt(aes_key, rsa_pub)
    rsa_aes_encrypt_time = time.perf_counter() - start
    
    # Encrypt the large message using AES
    start = time.perf_counter()
    nonce, aes_ciphertext, tag = aes_encrypt(message, aes_key)
    aes_encrypt_time = time.perf_counter() - start
    
    # Now, simulate decryption:
    # First, decrypt the AES key using RSA
    start = time.perf_counter()
    decrypted_aes_key = rsa_decrypt(encrypted_aes_key, rsa_priv)
    rsa_aes_decrypt_time = time.perf_counter() - start
    
    # Next, decrypt the message using the decrypted AES key
    start = time.perf_counter()
    decrypted_message = aes_decrypt(nonce, aes_ciphertext, tag, decrypted_aes_key)
    aes_decrypt_time = time.perf_counter() - start
    
    # Output results
    print("Hybrid Encryption Results:")
    print("RSA Key Generation Time: {:.4f}s".format(rsa_keygen_time))
    print("RSA AES Key Encryption Time: {:.4f}s".format(rsa_aes_encrypt_time))
    print("AES Encryption Time: {:.4f}s".format(aes_encrypt_time))
    print("RSA AES Key Decryption Time: {:.4f}s".format(rsa_aes_decrypt_time))
    print("AES Decryption Time: {:.4f}s".format(aes_decrypt_time))
    print("Decrypted Message Length:", len(decrypted_message), "characters")
