from tpm_security_onboard import string_to_bytes, get_random
from key_exchange_onboard import KEYFILE_OWN
import security_onboard


# KEYFILE = "keyblob.bin"

msg = "Hello world"

msg_bytes = string_to_bytes(msg)
msg_bytes_size = len(msg_bytes)

# RNG test
random_buffer = get_random(20)
if(random_buffer == None):
    print("Error generating random number!")
else:
    print("random_buffer = ", list(random_buffer))
print()

print("msg = " + msg)
print("msg_bytes_size = ", msg_bytes_size)
print("msg_bytes = ", list(msg_bytes))
print()

print("Loading key.......")
# RSA Keygen with Crypto library using TPM RNG
key = security_onboard.RSA_key_import(KEYFILE_OWN)
print("Key loaded.......")

enc_msg = security_onboard.RSA_encrypt(key.public_key(), msg_bytes)
if(enc_msg == None):
    print("Error with RSA encrypt!")
else:
    print("enc_msg = ", enc_msg)
    print()

# RSA Decrypt test
dec_msg = security_onboard.RSA_decrypt(key, enc_msg)
if(dec_msg == None):
    print("Error with RSA decrypt!")
else:
    print("msg = ", dec_msg)
    print()
