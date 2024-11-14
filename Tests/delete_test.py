import sys
sys.path.insert(1, "../")
from tpm_security import delete_TPM_nv

index = 2
print("Deleting key from TPM NV index:", index)
if delete_TPM_nv(index) == True:
    print("\t Key deleted successfully!")
else:
    print("\t Key delete ERROR!")