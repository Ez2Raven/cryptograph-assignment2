'''
    Utlity for AES encryption functions
'''
import os
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives import padding
from cryptography.hazmat.backends import default_backend


def encrypt(diffie_hellman_shared_key, message=b"A secret message"):
    '''
        Returns a tuple of (iv,ciphertext). The ciphertext is generated using CBC mode,
        a random iv and the diffie-hellman shared key.
        Padding must be used with CBC mode.
    '''
    padder = padding.PKCS7(128).padder()
    padded_data = padder.update(message) + padder.finalize()
    iv = os.urandom(16)
    cipher = Cipher(algorithms.AES(diffie_hellman_shared_key),
                    modes.CBC(iv), backend=default_backend())
    encryptor = cipher.encryptor()
    ciphertext = encryptor.update(padded_data) + encryptor.finalize()
    return (iv, ciphertext)


def decrypt(iv, ciphertext, diffie_hellman_shared_key):
    '''
        Returns the plaintext in bytes. Decrypted using the iv captured from the ciphertext.
    '''
    cipher = Cipher(algorithms.AES(diffie_hellman_shared_key),
                    modes.CBC(iv), backend=default_backend())
    decryptor = cipher.decryptor()
    padded_data = decryptor.update(ciphertext) + decryptor.finalize()
    unpadder = padding.PKCS7(128).unpadder()
    plaintext_bytes = unpadder.update(padded_data) + unpadder.finalize()
    return plaintext_bytes
