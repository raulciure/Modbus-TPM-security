from tpm_security_onboard_nv import string_to_bytes, get_random
import security_onboard_nv


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
key = security_onboard_nv.RSA_key_load()
print("Key loaded.......")

enc_msg = security_onboard_nv.RSA_encrypt_and_sign(key.public_key(), key, msg_bytes)
if(enc_msg == None):
    print("Error with RSA encrypt!")
else:
    print("enc_msg = ", enc_msg)
    print()

# RSA Decrypt test
dec_msg = security_onboard_nv.RSA_decrypt_and_verify(key, key.public_key(), enc_msg)
if(dec_msg == None):
    print("Error with RSA decrypt!")
else:
    print("msg = ", dec_msg)
    print()
