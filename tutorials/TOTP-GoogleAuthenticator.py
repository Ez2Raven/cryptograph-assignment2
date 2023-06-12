# https://pyauth.github.io/pyotp/#module-pyotp
# https://pypi.org/project/pyotp/
#
# Install google authenticator on your phone and scan the QR code
# in above URL link to setup account.  After that, run the following
# codes to observe the OTP in sync.
#
# You can also install the python authenticator library
# https://pypi.org/project/authenticator/
#
# pip install authenticator
#
# which functions like a console-based alternative to the phone app.
# You can also modiy codes in TOTP.py to connect with Google Authenticator.
import pyotp

totp = pyotp.TOTP("JBSWY3DPEHPK3PXP")
print("Current OTP:", totp.now())

totp_url = pyotp.totp.TOTP('JBSWY3DPEHPK3PXP').provisioning_uri(name='alice@google.com', issuer_name='Secure App')
print(pyotp.parse_uri(totp_url))