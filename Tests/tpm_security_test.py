import sys
sys.path.insert(1, "../")

from tpm_security import get_random, store_TPM_nv, read_TPM_nv, delete_TPM_nv

NV_INDEX = 0

# RNG test
random_buffer = get_random(256)
if(random_buffer == None):
    print("Error generating random number!")
else:
    print("random_buffer = ", list(random_buffer))
print()

# NV Store test
result = store_TPM_nv(random_buffer, NV_INDEX)
if result == False:
    print("ERROR storing buffer in TPM NV!")
print()

# NV Read test
result_buffer = read_TPM_nv(NV_INDEX)
print("Buffer read from TPM NV: \n ", list(result_buffer))
print()

# NV Delete test
result = delete_TPM_nv(NV_INDEX)
if result == False:
    print("ERROR deleting TPM NV index!")
