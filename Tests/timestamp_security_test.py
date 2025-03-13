import time
from Crypto.Util.Padding import pad, unpad
from Crypto.Cipher import AES
from pickle import dumps, loads
import random

message = "Hello world!".encode()

key = random.randbytes(32)

cipher = AES.new(key, AES.MODE_GCM)
nonce = cipher.nonce

timestamp = int(time.time()).to_bytes(4)
cipher.update(timestamp)

enc_tuple = cipher.encrypt_and_digest(pad(message, AES.block_size))
enc_data = dumps((nonce, timestamp, enc_tuple))

print("message = ", message)
print("nonce = ", nonce)
print("timestamp (bytes) = ", timestamp)
print("enc_data = ", enc_data)
print("------------------------------------------------")

# DECRYPT

(nonce, timestamp_msg, (ciphertext, MAC_tag)) = loads(enc_data)
cipher = AES.new(key, AES.MODE_GCM, nonce=nonce)

timestamp_now = int(time.time())

try:
    cipher.update(timestamp_msg)
    msg = unpad(cipher.decrypt_and_verify(ciphertext, MAC_tag), AES.block_size)
    if(timestamp_now - int.from_bytes(timestamp_msg) >= 1):    # Verify timestamp
        print("!!! Timestamp is different !!!")
        raise ValueError
except(ValueError):
    raise

print("message = ", message)
print("nonce = ", nonce)
print("timestamp_msg = ", int.from_bytes(timestamp_msg))
print("timestamp_now = ", timestamp_now)
