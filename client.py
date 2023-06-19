'''
    Entry point for server application.
'''

import binascii
import os
import datetime
import socket
import time
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import x25519
from crypto_utils import x509Util
from crypto_utils import ecdh_x25519
from crypto_utils import aes256

# Networking Settings
SERVER = 'localhost'  # The server's hostname or IP address
PORT = 65432        # The port used by the server
BUFFER_SIZE = 2048

# X25519 File Storage Settings
OUTPUT_DIR = 'client_output'
X25519_PRIVATE_KEY_FILEPATH = os.path.join(OUTPUT_DIR, 'client-x25519.key')
X25519_PUBLIC_KEY_FILEPATH = os.path.join(OUTPUT_DIR, 'client-x25519.pub')
X25519_PRIVATE_KEY_PASSPHRASE = b'password'

# X509 File Storage Settings
X509_PRIVATE_KEY_FILEPATH = os.path.join(OUTPUT_DIR, 'client-id-rsa.key')
X509_PUBLIC_CERT_FILEPATH = os.path.join(OUTPUT_DIR, 'client-id.x509')
X509_PRIVATE_KEY_PASSPHRASE = b'password'
TRUSTED_SERVER_X509_PUBLIC_CERT_FILEPATH = os.path.join(
    'server_output', 'server-id.x509')


def connect(server_ip_address, port, trusted_server_fingerprint, ecdh_private_key, ecdh_public_key):
    '''
        1. Connects to server via insecure TCP communication channel.
        2. Wait to receive server PKI public certificate for authentication.
        3. Calculate the digest of the public certificate.
        4. Compare the digest against fingerprint from a trusted certificate store.
        4. Calculate the shared key to create the cipher for symmetric encryption
        5. Prompt user for message input
        6. Sends the encrypted message to client
        7. Wait to receive encrypted message from client
        8. Decrypt and print decrypted message from client
    '''

    x25519_public_key_bytes = ecdh_public_key.public_bytes_raw()

    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        s.connect((server_ip_address, port))
        print(f'Connected to server: {server_ip_address}:{port}')
        server_pki_public_cert_bytes = s.recv(BUFFER_SIZE)
        print(
            'Received server pki public key for authentication:\n' +
            f'{server_pki_public_cert_bytes.decode()}')

        time.sleep(3)

        # compare fingerprint from trusted storage and from the server
        untrusted_fingerprint = x509Util.cert_fingerprint_from_bytes(
            server_pki_public_cert_bytes)
        if untrusted_fingerprint != trusted_server_fingerprint:
            raise Exception(
                "Fingerprint from TCP stream does not match with fingerprint from trusted storage.")

        # Send client x25519 public key for ECDH handshake
        s.sendall(x25519_public_key_bytes)
        print(
            f'Sent client x25519 public key to server: {len(x25519_public_key_bytes)} bytes.')

        time.sleep(3)

        # wait for server to send its x25519 public cert for ECDH handshake
        server_x25519_public_key_data = s.recv(BUFFER_SIZE)
        print(
            'Received server x25519 public key for ecdh key exchange:\n' +
            f'{len(server_x25519_public_key_data)} bytes.')

        time.sleep(3)

        server_x25519_public_key = x25519.X25519PublicKey.from_public_bytes(
            server_x25519_public_key_data)

        shared_key = ecdh_x25519.generate_derived_key(
            private_key=ecdh_private_key,
            peer_public_key=server_x25519_public_key,
            agreed_algorithm=hashes.SHA256(),
            agreed_length=32,
            agreed_info=b'handshake data')

        print(
            f'Client derived shared key: {binascii.hexlify(shared_key).decode()}')

        # note that cbc mode is used, a random iv must be used for each message
        (iv, ciphertext) = aes256.encrypt(
            diffie_hellman_shared_key=shared_key,
            message=b'secret message from client.'
        )
        # prepend the iv to the ciphertext
        s.sendall(iv+ciphertext)

        time.sleep(3)

        # Waiting for client's command/inputs
        server_message = s.recv(BUFFER_SIZE)
        iv2 = server_message[:16]
        ciphertext2 = server_message[16:]
        plaintext = aes256.decrypt(iv2, ciphertext2, shared_key)
        print('Received from server:\n', plaintext)


if __name__ == '__main__':

    # Setup for X509 PKI
    x509_private_key = x509Util.generate_private_key(
        public_exponent=65537, key_size=2048)
    x509Util.write_private_key_to_file(
        private_key=x509_private_key,
        filepath=X509_PRIVATE_KEY_FILEPATH,
        passphase=X509_PRIVATE_KEY_PASSPHRASE)

    x509_public_cert = x509Util.generate_public_cert(
        private_key=x509_private_key,
        country='SG',
        state='SG',
        locality='SG',
        organization='Swdev Ninja',
        common_name='client.localhost',
        validity=datetime.timedelta(days=30),
        dns_name='localhost',
        hash_function=hashes.SHA256())

    x509Util.write_public_key_to_file(
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

    # Since the server.py will always generate a new x509 certificate after execution,
    # We'll simulate accquiring a trusted fingerprint from a trusted certstore.
    # This fingerprint will be used for authenticating the server later.
    SERVER_HOST_KEY_FINGERPRINT = x509Util.cert_fingerprint_from_file(
        TRUSTED_SERVER_X509_PUBLIC_CERT_FILEPATH, hashes.SHA256())

    connect(SERVER, PORT, SERVER_HOST_KEY_FINGERPRINT,
            ephermal_key_pair[0], ephermal_key_pair[1])
