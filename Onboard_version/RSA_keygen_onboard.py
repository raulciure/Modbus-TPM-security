from Crypto.PublicKey import RSA
from tpm_security_onboard import get_random
from security_onboard import RSA_key_export
from key_exchange_onboard import KEYFILE_OWN
import time

# Generates a new RSA key-pair using TPM RNG and exports it to file
def RSA_keygen(output_file):
    print("Generating key.......")
    start_time = time.time()    # Start measuring time taken to generate key
    key = RSA.generate(2048, get_random)
    end_time = time.time()
    print("Key generation finished.\nTime taken: ",  end_time - start_time, " seconds")

    RSA_key_export(key, output_file)
    # exported_key = key.exportKey('DER', None, pkcs=8, protection='PBKDF2WithHMAC-SHA512AndAES256-CBC', randfunc=get_random)

    # with open(output_file, "wb") as binary_file:
    #     binary_file.write(exported_key)


RSA_keygen(KEYFILE_OWN)