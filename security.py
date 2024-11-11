# module containing functions used for security operations

from tpm_security import get_random, read_TPM_nv
from Crypto.Cipher import AES
from Crypto.Cipher import PKCS1_OAEP
from Crypto.PublicKey import RSA
from Crypto.Util.Padding import pad, unpad
from Crypto.Signature import pss
from Crypto.Hash import SHA256
from pickle import dumps, loads


# generates an AES-256 key
def AES_key_gen():
    key = get_random(32)

    if(key == None):
        # retry 10 times to get key
        counter = 0
        while(key == None and counter < 10):
            key = get_random(32)
            counter += 1

    if(key != None):
        return key
    else:
        # print("Error generating AES key!")
        return None


# function that encrypts message using AES-GCM AEAD
# returns serialized nonce & enc_tuple
def AES_encrypt_and_digest(key : bytes, msg : bytes):
    cipher = AES.new(key, AES.MODE_GCM)
    nonce = cipher.nonce

    enc_tuple = cipher.encrypt_and_digest(pad(msg, AES.block_size))

    enc_data = dumps((nonce, enc_tuple))

    return enc_data


# function that decrypts & authenticates message using AES-GCM AEAD
# returns original message
def AES_decrypt_and_verify(key : bytes, enc_data : bytes):
    (nonce, (ciphertext, MAC_tag)) = loads(enc_data)

    cipher = AES.new(key, AES.MODE_GCM, nonce=nonce)

    try:
        msg = unpad(cipher.decrypt_and_verify(ciphertext, MAC_tag), AES.block_size)
        return msg
    except(ValueError):
        raise


# function that encrypts message using RSA - PKCS1_OAEP with a public key and signs encrypted message using PKCS1_PSS with a private key
# returns serialized tuple of encrypted message and signature
def RSA_encrypt_and_sign(enc_key, sign_key, msg : bytes):
    cipher = PKCS1_OAEP.new(enc_key)

    enc_msg = cipher.encrypt(msg)
    h = SHA256.new(enc_msg)
    signature = pss.new(sign_key).sign(h)

    return dumps((enc_msg, signature))


# function that decrypts message using RSA - PKCS1_OAEP with a private key and verifies encrypted message using PKCS1_PSS with a public key
# returns decrypted message or raises ValueError exception if signature can't be verified
def RSA_decrypt_and_verify(dec_key, verif_key, enc_msg : bytes):
    cipher = PKCS1_OAEP.new(dec_key)

    (enc_msg, signature) = loads(enc_msg)

    h = SHA256.new(enc_msg)
    verifier = pss.new(verif_key)
    try:
        verifier.verify(h, signature)
        return cipher.decrypt(enc_msg)
    except (ValueError):
        raise


# Converts key from DER format to RsaKey object
def RSA_key_load(encoded_key):
    key = RSA.import_key(encoded_key, None)
    return key


# Reads key and converts it from DER format to RsaKey object
def RSA_key_read_and_load(index : int):
    encoded_key = RSA_key_read(index)

    key = RSA.import_key(encoded_key, None)
    return key


# Serializes a DER encoded key into a tuple containing size and the encoded key
def RSA_key_serialize(encoded_key : bytes):
    encoded_key_len = len(encoded_key)
    encoded_key_tuple = (encoded_key_len, encoded_key)
    serialized_data = dumps(encoded_key_tuple)

    return serialized_data


# Export key to DER format wtih option to return serialized bytes of tuple containing size and the formated key (used for TPM NV storage)
def RSA_key_export(key : RSA.RsaKey, serialize_size=False):
    exported_key = key.export_key(format='DER', passphrase=None, pkcs=8, protection='PBKDF2WithHMAC-SHA512AndAES256-CBC', randfunc=get_random)

    if(serialize_size == True):
        return RSA_key_serialize(exported_key)
    
    return exported_key


# Reads binary encoded key from TPM NV storage (in serialized form) & returns only the DER encoded RSA key (default) or the entire NV buffer raw_data, as provided by the TPM API
def RSA_key_read(index : int, raw_data=False) -> bytes | None:
    encoded_key = read_TPM_nv(index)

    if(encoded_key == None):
        print("Error reading NV key!")
        return None
    
    if(raw_data == True):
        return encoded_key

    (encoded_key_len, encoded_key_trimmed) = loads(encoded_key)
    encoded_key_trimmed = encoded_key_trimmed[:encoded_key_len]

    return encoded_key_trimmed
