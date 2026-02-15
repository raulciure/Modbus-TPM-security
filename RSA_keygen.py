from Crypto.PublicKey import RSA
from tpm_security import get_random, store_TPM_nv, delete_TPM_nv, OWN_KEY_NV_INDEX
from security import RSA_key_export
import time


# Generates a new RSA key-pair using TPM RNG and stores it in TPM NV storage at index nv_index
def RSA_keygen(nv_index):
    # delete old key from NV storage
    print("Deleting old key from NV......")
    delete_TPM_nv(nv_index)
    print("Old key deleted!")

    # generate new key
    print("Generating key.......")
    start_time = time.time()    # Start measuring time taken to generate key
    key = RSA.generate(2048, get_random)    # type: ignore
    end_time = time.time()
    print("Key generation finished.\nTime taken: ",  end_time - start_time, " seconds")

    exported_key = RSA_key_export(key, serialize_size=True)

    # store exported key in TPM NV storage
    status = store_TPM_nv(exported_key, nv_index)
    if(status == True):
        print("Storage of the key successful!")
    else:
        print("!!! KEY STORAGE FAILED !!!")


if __name__ == "__main__":
    RSA_keygen(OWN_KEY_NV_INDEX)
