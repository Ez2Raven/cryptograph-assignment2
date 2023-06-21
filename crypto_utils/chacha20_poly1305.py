from cryptography.hazmat.primitives.ciphers.aead import ChaCha20Poly1305


def encrypt(key, nonce, plaintext, associated_data=b'authenticated but unencrypted data'):
    '''
        Encrypts using chacha20 poly1305 stream cipher
    '''

    # Create the ChaCha20-Poly1305 cipher object
    chacha = ChaCha20Poly1305(key)

    # Encrypt the plaintext using ChaCha20-Poly1305
    ciphertext = chacha.encrypt(nonce, plaintext, associated_data)

    return ciphertext


def decrypt(key, nonce, ciphertext, associated_data=b'authenticated but unencrypted data'):
    '''
        Decrypts using chacha20 poly1305 stream cipher
    '''

    # Create the ChaCha20-Poly1305 cipher object
    chacha = ChaCha20Poly1305(key)
    plaintext = chacha.decrypt(nonce, ciphertext, associated_data)

    return plaintext
