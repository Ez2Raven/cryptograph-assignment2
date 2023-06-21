'''
    Utlity for AES encryption functions
'''
import os
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives import padding
from cryptography.hazmat.backends import default_backend


def encrypt(diffie_hellman_shared_key, message=b"A secret message"):
    '''
        Encrypts the plaintext message using the provided secret key.
        PKCS7 padding will be applied to the plaintext to ensure
        encryption can be applied consistently to all blocks.

        IV of 16 bytes is returned along with ciphertext for transmission.
    '''

    # AES block size is fixed at 128 bits, regardless of the key size used.
    padder = padding.PKCS7(128).padder()

    # Add bytes to ensure plaintext length is a mulitiple of AES block size.
    # so that encryption can be applied consistently to all blocks.
    padded_data = padder.update(message) + padder.finalize()

    # 16 bytes (128 bits) IV aligns with the block size of AES 
    iv = os.urandom(16)

    cipher = Cipher(algorithms.AES256(diffie_hellman_shared_key),
                    modes.CBC(iv), backend=default_backend())
    encryptor = cipher.encryptor()
    
    # encrypts the padded data
    ciphertext = encryptor.update(padded_data) + encryptor.finalize()
    return (iv, ciphertext)


def decrypt(iv, ciphertext, diffie_hellman_shared_key):
    '''
        Decrypts the ciphertext susing the provided secret key.
        PKCS7 padding will be removed from the decrpyted to ensure
        the plaintext can be consumed by subsequent processing.
    '''
    cipher = Cipher(algorithms.AES256(diffie_hellman_shared_key),
                    modes.CBC(iv), backend=default_backend())
    decryptor = cipher.decryptor()

    # decrypt the data before unpadding
    padded_data = decryptor.update(ciphertext) + decryptor.finalize()
    # AES block size is fixed at 128 bits, regardless of the key size used.
    unpadder = padding.PKCS7(128).unpadder()
    # remove the extra bytes padded to the plaintext
    plaintext_bytes = unpadder.update(padded_data) + unpadder.finalize()
    return plaintext_bytes
