from ..security import *
from ..tpm_security import string_to_bytes


msg = "Hello there!"
key = "vfbxEsPCj1g46wlNQSlUdEUe7U4nFb59"

enc_msg = AES_encrypt_and_digest(string_to_bytes(key), string_to_bytes(msg))

print("enc_msg_size = ", len(enc_msg))

print("enc_msg = ", enc_msg)

dec_msg = AES_decrypt_and_verify(string_to_bytes(key), enc_msg)

print("dec_msg = ", enc_msg)