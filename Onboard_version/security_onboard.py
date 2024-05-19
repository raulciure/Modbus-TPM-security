# file containing functions used for security operations, other than those that use the TPM

from tpm_security_onboard import get_random
# from Crypto.Protocol.KDF import PBKDF2
from Crypto.Cipher import AES
from Crypto.Util.Padding import pad, unpad
# from Crypto.Random import get_random_bytes
from pickle import dumps, loads
from time import sleep

# For RSA (if used)
from Crypto.Cipher import PKCS1_OAEP
from Crypto.PublicKey import RSA


# def AES_example():
#     # salt = TPM_get_random(32)
#     # password = TPM_get_random(32)

#     message = b"Hello World!"

#     salt = get_random_bytes(32)
#     password = get_random_bytes(32)

#     print("salt = " + str(salt) + "\n")
#     print("password = " + str(password) + "\n")

#     key = PBKDF2(password, salt, dkLen=32)

#     cipher = AES.new(key, AES.MODE_GCM)
#     # iv = cipher.iv # for CBC
#     nonce = cipher.nonce # for GCM

#     # cipher_data = cipher.encrypt(pad(message, AES.block_size))
    
#     gcm_result = cipher.encrypt_and_digest(pad(message, AES.block_size))

#     # print("cipher_data = " + str(cipher_data) + "\n")

#     print("cipher_data = " + str(gcm_result[0]) + "\n")
#     print("MAC_tag = " + str(gcm_result[1]) + "\n")

#     cipher_dest = AES.new(key, AES.MODE_GCM, nonce=nonce)
    
#     orig_msg = unpad(cipher_dest.decrypt_and_verify(gcm_result[0], gcm_result[1]), AES.block_size)

#     print("original message = " + str(orig_msg) + "\n")


# generates a AES-256 key
def AES_key_gen():
    key = get_random(32)
    # key_size = int(32)   # bytes

    if(key == None):
        # retry 10 times to get key
        counter = 0
        while(key == None and counter < 10):
            sleep(0.25)
            key = get_random(32)

    if(key != None):
        return key
    else:
        # print("Error generating AES key!")
        return None


# function that encrypts message using GCM AEAD
# returns serialized nonce & enc_tuple //tuple of nonce, ciphertext and the generated MAC tag
def AES_encrypt_and_digest(key : bytes, msg : bytes):
    cipher = AES.new(key, AES.MODE_GCM)
    nonce = cipher.nonce

    enc_tuple = cipher.encrypt_and_digest(pad(msg, AES.block_size))

    enc_data = dumps((nonce, enc_tuple))

    # return (nonce, enc_tuple)
    return enc_data


# function that decrypts & authenticates message using GCM AEAD
# return orignial message
# def AES_decrypt_and_verify(key : bytes, nonce : bytes, enc_tuple):
def AES_decrypt_and_verify(key : bytes, enc_data : bytes):
    (nonce, (ciphertext, MAC_tag)) = loads(enc_data)

    cipher = AES.new(key, AES.MODE_GCM, nonce=nonce)

    # (ciphertext, MAC_tag) = enc_tuple

    try:
        msg = unpad(cipher.decrypt_and_verify(ciphertext, MAC_tag), AES.block_size)
        return msg
    except(ValueError):
        raise


# function that encrypts message using RSA - PKCS1_OAEP
# returns encrypted message or None if cipher can't encrypt
def RSA_encrypt(public_key, msg : bytes):
    # imported_pub_key = RSA.import_key(public_key)
    cipher = PKCS1_OAEP.new(public_key)

    return cipher.encrypt(msg)


# function that decrypts message using RSA - PKCS1_OAEP
# returns decrypted message or None if cipher can't decrypt
def RSA_decrypt(key, enc_msg : bytes):
    # imported_priv_key = RSA.import_key(private_key)
    cipher = PKCS1_OAEP.new(key)

    return cipher.decrypt(enc_msg)


# Reads binary form of key & converts it to RsaKey object
def RSA_key_import(input_file):
    with open(input_file, "rb") as binary_file:
        imported_key = binary_file.read()
    key = RSA.import_key(imported_key, None)
    return key


# Export key to DER format, writes it to file if given output file and returns bytes of that format
def RSA_key_export(key : RSA.RsaKey, output_file : str=None):
    exported_key = key.export_key(format='DER', passphrase=None, pkcs=8, protection='PBKDF2WithHMAC-SHA512AndAES256-CBC', randfunc=get_random)

    if(output_file != None):
        with open(output_file, "wb") as binary_file:
            binary_file.write(exported_key)

    return exported_key


# Reads binary encoded file containing key
def RSA_key_read(input_file):
    with open(input_file, "rb") as binary_file:
        imported_key = binary_file.read()
    return imported_key


# TEST begin
# msg = "Hello world!"

# msg_bytes = msg.encode("utf-8")
# msg_bytes_size = len(msg_bytes)

# key = RSA_keygen()

# enc_msg = RSA_encrypt(key.public_key(), msg_bytes)
# if(enc_msg == None):
#     print("Error with RSA encrypt!")
# else:
#     print("enc_msg = ", enc_msg)
#     print()

# # RSA Decrypt test
# dec_msg = RSA_decrypt(key, enc_msg)
# if(dec_msg == None):
#     print("Error with RSA decrypt!")
# else:
#     print("msg = ", dec_msg)
#     print()