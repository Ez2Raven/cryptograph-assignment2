"""
    Utlity for ECDH X25519 key exchange functions
"""

from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric.x25519 import X25519PrivateKey
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.primitives import serialization


def generate_keys():
    """
        Returns tuple of private and public keys that will be used for ephemeral key exchange
    """
    private_key = X25519PrivateKey.generate()
    public_key = private_key.public_key()
    return (private_key, public_key)


def generate_derived_key(private_key, peer_public_key,
                         agreed_algorithm=hashes.SHA256(),
                         agreed_length=32,
                         agreed_info=b'handshake data'):
    """
        Calculates and returns a derived key using the host's private key, peer's public key and
        agreed parameters for the handshake.
    """
    shared_key = private_key.exchange(peer_public_key)
    # Perform key derivation.
    derived_key = HKDF(
        algorithm=agreed_algorithm,
        length=agreed_length,
        salt=None,
        info=agreed_info,
    ).derive(shared_key)
    return derived_key


def write_private_key_to_file(private_key, filepath, passphrase=b'passphrase'):
    '''
        Saves the private key into the provided filepath in PEM encoding, in pkcs8 format.
        Overwrites the existing file, if it already exists.
        Private key is protected using passphrase
        X25519 private key is approximately 95 to 100 bytes in size.
    '''
    try:
        key_bytes = private_key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.PKCS8,
            encryption_algorithm=serialization.BestAvailableEncryption(passphrase))

        print(
            f'[Write private key to disk] PEM encoding, PKCS8 format:\n{key_bytes.decode()}')

        with open(filepath, 'wb') as file:
            file.write(key_bytes)
        print('[Write private key to disk] ' +
              f'Successfully written to relative path: {filepath}\n')
    except Exception as exception:
        # Pokemon catch, because i'm new to python
        print('[Write private key to disk]' +
              f'Error occurred while writing the private key to file: {exception}\n')


def write_public_key_to_file(public_key, filepath):
    '''
        Saves the private key into the provided filepath in PEM encoding + pkcs8 format.
        Overwrites the existing file, if it already exists.
    '''
    try:
        key_bytes = public_key.public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo)

        print('[Write public key to disk]' +
              f'PEM encoding, SPKI format:\n{key_bytes.decode()}')

        with open(filepath, 'wb') as file:
            file.write(key_bytes)
        print('[Write public key to disk] ' +
              f'Successfully written to relative path: {filepath}\n')
    except Exception as exception:
        # Pokemon catch, because i'm new to python
        print('[Write public key to disk]' +
              f'Error occurred while writing the public key to file: {exception}\n')
