"""
    Utlity for x509cert functions.
    Defaults to PEM encoding, TraditionalOpenSSL Format
"""
import datetime
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography.hazmat.backends import default_backend
from cryptography import x509
from cryptography.x509.oid import NameOID
from cryptography.hazmat.primitives import hashes


def generate_private_key(public_exponent=65537, key_size=2048):
    '''
        Generate the private key that will be used to sign the x509 certificate.
    '''
    key = rsa.generate_private_key(
        public_exponent,
        key_size
    )
    return key


def write_private_key_to_file(private_key, filepath, passphase=b"passphrase"):
    '''
        Writes the private key into the provided filepath in PEM encoding, in OpenSSL format.
        Private key is protected using passphrase
        Overwrites the existing file, if it already exists.
    '''
    try:
        key_bytes = private_key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.TraditionalOpenSSL,
            encryption_algorithm=serialization.BestAvailableEncryption(
                passphase)
        )

        print('[Write public cert to disk]' +
              f'PEM encoding:\n{key_bytes.decode()}')

        with open(filepath, "wb") as file:
            file.write(key_bytes)

        print('[Write private cert to disk] ' +
              f'Successfully written to relative path: {filepath}\n')
    except Exception as exception:
        # Pokemon catch, because i'm new to python
        print('[Write private cert to disk]' +
              f'Error occurred while writing the public cert to file: {exception}\n')


def generate_public_cert(private_key,
                         country, state, locality, organization, common_name,
                         validity=datetime.timedelta(days=10),
                         dns_name='localhost',
                         hash_function=hashes.SHA256()):
    '''
        Generate a x509 public cert with a default validity of 10 days.
        Defaults to SHA256 when signing the certificate with provided private key
    '''
    subject = issuer = x509.Name([
        x509.NameAttribute(NameOID.COUNTRY_NAME, country),
        x509.NameAttribute(NameOID.STATE_OR_PROVINCE_NAME, state),
        x509.NameAttribute(NameOID.LOCALITY_NAME, locality),
        x509.NameAttribute(NameOID.ORGANIZATION_NAME, organization),
        x509.NameAttribute(NameOID.COMMON_NAME, common_name),
    ])
    cert = x509.CertificateBuilder().subject_name(
        subject
    ).issuer_name(
        issuer
    ).public_key(
        private_key.public_key()
    ).serial_number(
        x509.random_serial_number()
    ).not_valid_before(
        datetime.datetime.utcnow()
    ).not_valid_after(
        # Our certificate will be valid for 10 days
        datetime.datetime.utcnow() + validity
    ).add_extension(
        x509.SubjectAlternativeName([x509.DNSName(dns_name)]),
        critical=False,
    ).sign(private_key, hash_function)
    return cert


def write_public_key_to_file(public_cert, filepath):
    '''
        Saves the private key into the provided filepath in PEM encoding, in pkcs8 format.
        Overwrites the existing file, if it already exists.
    '''
    try:
        key_bytes = public_cert.public_bytes(
            encoding=serialization.Encoding.PEM)

        print('[Write public cert to disk]' +
              f'PEM encoding:\n{key_bytes.decode()}')

        with open(filepath, 'wb') as file:
            file.write(key_bytes)

        print('[Write public cert to disk] ' +
              f'Successfully written to relative path: {filepath}\n')
    except Exception as exception:
        # Pokemon catch, because i'm new to python
        print('[Write public cert to disk]' +
              f'Error occurred while writing the public cert to file: {exception}\n')


def cert_fingerprint_from_file(filepath, hash_function=hashes.SHA256()):
    '''
        Returns the certifcate fingerprint from a file.
        This function is typically used to return the fingerprint from a trusted cert store
        to compare against with an untrusted certificate
    '''
    with open(filepath, "rb") as cert_file:
        cert_data = cert_file.read()

    cert = x509.load_pem_x509_certificate(cert_data, default_backend())
    fingerprint = cert.fingerprint(hash_function)
    print(
        f'X509 Certificate Location: {filepath}\nFingerprint: {fingerprint.hex()}')
    return fingerprint


def cert_fingerprint_from_bytes(cert_bytes, hash_function=hashes.SHA256()):
    '''
        Returns the certifcate fingerprint from bytes.
        This function is typically used to return the cert fingerprint originating from a data stream
        to compare against with an trusted certificate
    '''
    cert = x509.load_pem_x509_certificate(cert_bytes)
    fingerprint = cert.fingerprint(hash_function)
    print(f'Fingerprint from bytes: {fingerprint.hex()}')
    return fingerprint


def sign_message(private_key, plaintext):
    '''
        Signs the message using
        MGF1 and PSS padding to ensure the security and uniqueness of the generated padding
        uses sha256 for hashing
    '''
    signature = private_key.sign(
        plaintext,
        padding.PSS(
            mgf=padding.MGF1(hashes.SHA256()),
            salt_length=padding.PSS.MAX_LENGTH
        ),
        hashes.SHA256()
    )
    return signature

def verify_message(cert_bytes, signature, message):
    '''
        Verify the message using
        MGF1 and PSS padding to ensure the security and uniqueness of the generated padding
        uses sha256 for hashing
    '''
    
    certificate = x509.load_pem_x509_certificate(cert_bytes, default_backend())
    public_key=certificate.public_key()
    
    try:
        public_key.verify(
            signature,
            message,
            padding.PSS(
                mgf=padding.MGF1(hashes.SHA256()),
                salt_length=padding.PSS.MAX_LENGTH
            ),
            hashes.SHA256()
        )
        print("Signature is valid. Message is authentic.")
    except Exception as ex:
        print(f"Signature verification failed. Message may have been tampered with or the public key is incorrect.\n{ex}")