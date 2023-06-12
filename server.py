'''
    Entry point for server application.
'''

import os
import datetime
import socket
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives import serialization
from crypto_utils import x509cert
from crypto_utils import ecdh_x25519

# Networking Settings
HOST = 'localhost'  # The server's hostname or IP address
PORT = 65432        # The port used by the server

# X25519 File Storage Settings
OUTPUT_DIR = 'server_output'
X25519_PRIVATE_KEY_FILEPATH = os.path.join(OUTPUT_DIR, 'server-x25519.key')
X25519_PUBLIC_KEY_FILEPATH = os.path.join(OUTPUT_DIR, 'server-x25519.pub')
X25519_PRIVATE_KEY_PASSPHRASE = b'password'

# X509 File Storage Settings
X509_PRIVATE_KEY_FILEPATH = os.path.join(OUTPUT_DIR, 'server-id-rsa.key')
X509_PUBLIC_CERT_FILEPATH = os.path.join(OUTPUT_DIR, 'server-id.x509')
X509_PRIVATE_KEY_PASSPHRASE = b'password'

if __name__ == '__main__':

    # Setup for X509 PKI
    x509_private_key = x509cert.generate_private_key(
        public_exponent=65537, key_size=2048)
    x509cert.write_private_key_to_file(
        private_key=x509_private_key,
        filepath=X509_PRIVATE_KEY_FILEPATH,
        passphase=X509_PRIVATE_KEY_PASSPHRASE)

    x509_public_cert = x509cert.generate_public_cert(
        private_key=x509_private_key,
        country='SG',
        state='SG',
        locality='SG',
        organization='Swdev Ninja',
        common_name='localhost',
        validity=datetime.timedelta(days=30),
        dns_name='localhost',
        hash_function=hashes.SHA256())

    x509cert.write_public_key_to_file(
        x509_public_cert, X509_PUBLIC_CERT_FILEPATH)

    # Setup for Diffie-Hellman key exchange
    ephermal_key_pair = ecdh_x25519.generate_keys()
    # save ephermal keys to file for visual inspection
    ecdh_x25519.write_private_key_to_file(
        private_key=ephermal_key_pair[0],
        filepath=X25519_PRIVATE_KEY_FILEPATH,
        passphrase=X25519_PRIVATE_KEY_PASSPHRASE)
    ecdh_x25519.write_public_key_to_file(
        public_key=ephermal_key_pair[1],
        filepath=X25519_PUBLIC_KEY_FILEPATH)


def listen(ip, port, host_public_key):
    '''
        1. Opens an insecure TCP communication channel.
        2. Reads and sends host's PKI public certificate to client for authentication.
        3. Waits for client to send its x25519 public key as peer_public_key
        4. Calculate the shared key to create the cipher for symmetric encryption
        5. Prompt user for message input
        6. Sends the encrypted message to client
        7. Wait to receive encrypted message from client
        8. Decrypt and print decrypted message from client
    '''
    # with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
    #     s.bind((HOST, PORT))
    #     s.listen()
    #     conn, addr = s.accept()
    #     with conn:
    #         print(f'{addr} has connected to this server')
    #         print(f'Sending host public key to client for authentication:')

    #         conn.sendall(host_public_key.public_bytes(
    #         encoding=serialization.Encoding.Raw,
    #         format=serialization.PublicFormat.SubjectPublicKeyInfo))
