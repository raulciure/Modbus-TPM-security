from Crypto.PublicKey import RSA
from Crypto.Signature import pss
from Crypto.Hash import SHA256
from Crypto.PublicKey import ECC
from Crypto.Protocol import DH
from Crypto.Protocol.KDF import HKDF
from pickle import dumps, loads
from src.modbus_tpm_security.tpm_security import read_TPM_nv


# Sign message with RSA private key using PKCS1_PSS
# Return: serialized tuple of message and signature
def RSA_sign(sign_key : RSA.RsaKey, msg : bytes):
    h = SHA256.new(msg)
    signature = pss.new(sign_key, rand_func).sign(h)     # type: ignore

    return dumps((msg, signature))


# Verfy message signature using PKCS1_PSS with RSA public key
# Return: authenticated message
def RSA_verify(verif_key : RSA.RsaKey, signed_message_encoded : bytes):
    (msg, signature) = loads(signed_message_encoded)

    h = SHA256.new(msg)
    verifier = pss.new(verif_key)     # type: ignore
    try:
        verifier.verify(h, signature)   # type: ignore
        return msg
    except (ValueError):
        raise


# Converts key from DER format to RsaKey object
def RSA_key_load(encoded_key):
    key = RSA.import_key(encoded_key, None)
    return key


# Reads key and converts it from DER format to RsaKey object
def RSA_key_read_and_load(index : int):
    encoded_key = RSA_key_read(index)

    key = RSA.import_key(encoded_key, None)     # type: ignore
    return key


# Serializes a DER encoded key into a tuple containing size and the encoded key
def RSA_key_serialize(encoded_key : bytes):
    encoded_key_len = len(encoded_key)
    encoded_key_tuple = (encoded_key_len, encoded_key)
    serialized_data = dumps(encoded_key_tuple)

    return serialized_data


# Export key to DER format wtih option to return serialized bytes of tuple containing size and the formated key (used for TPM NV storage)
def RSA_key_export(key : RSA.RsaKey, serialize_size=False):
    exported_key = key.export_key(format='DER', passphrase=None, pkcs=8, protection='PBKDF2WithHMAC-SHA512AndAES256-CBC')  # type: ignore

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


# ECDHE / ECC functions

# Generate an ECC key
def ECC_key_gen() -> ECC.EccKey:
    ECC_CURVE = "Curve25519"    # X25519 key exchange protocol
    key = ECC.generate(curve=ECC_CURVE)    # type: ignore
    return key


# Export ECC key to bytes
def ECC_key_export(key : ECC.EccKey) -> bytes:
    exported_key = key.export_key(format='raw')
    return exported_key


def ECC_public_key_import(encoded_key : bytes) -> ECC.EccKey:
    key = DH.import_x25519_public_key(encoded_key)
    return key


# Create a common key based on both parties keys
def ECDHE_key_agreement(own_key : ECC.EccKey, peer_key : ECC.EccKey) -> bytes:
    def kdf(input):
        SALT = bytes.fromhex("839afe43f662ad7517481b1399026c248eecf00caa8db56db846245b867e886a")
        return HKDF(input, key_len=32, salt=SALT, hashmod=SHA256)

    session_key = DH.key_agreement(eph_priv=own_key, eph_pub=peer_key, kdf=kdf)

    if isinstance(session_key, tuple):
        raise AssertionError("[ECDHE_key_agreement] session_key is a tuple (i.e. KDF created multiple keys)")
    return session_key