from tpm_security import *


KEYFILE = "keyblob.bin"

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

# Keygen test
result = RSA_key_gen2(KEYFILE)
if(result == None):
    print("Error generating RSA key!")
else:
    key_pub_buffer = result[1]
    key_pub_buffer_size = result[2]
    key_priv_buffer = result[3]
    key_priv_buffer_size = result[4]
    print("key_pub_buffer_size = ", key_pub_buffer_size)
    print("key_pub_buffer = ", list(key_pub_buffer))
    print("key_priv_buffer_size = ", key_priv_buffer_size)
    print("key_priv_buffer = ", list(key_priv_buffer))
    print()

# RSA Encrypt test
result = RSA_encrypt(key_pub_buffer, key_pub_buffer_size, msg_bytes, msg_bytes_size)
if(result == None):
    print("Error with RSA encrypt!")
else:
    (output, output_size) = result
    print("output_size = ", output_size)
    print("output = ", list(output)[:output_size])
    print()

# RSA Decrypt test
result = RSA_decrypt(KEYFILE, output, output_size)
if(result == None):
    print("Error with RSA decrypt!")
else:
    (msg_output_bytes, msg_output_bytes_size) = result
    print("msg_output_bytes_size = ", msg_output_bytes_size)
    print("msg_output_bytes = ", list(msg_output_bytes)[:msg_output_bytes_size])
    print("decrypted message = " + bytes_to_string(msg_output_bytes))
    print()
