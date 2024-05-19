import ctypes


MAX_RSA_PUB_KEY_BYTES = 512
MAX_RSA_KEY_BYTES = 1024
MAX_NV_STORAGE_SIZE_BYTES = 1536

tpm_api_library = ctypes.CDLL("/home/raul/Desktop/Packets_security/tpm_api.so")


def string_to_bytes(input : str):
    return input.encode('utf-8')


def bytes_to_string(input : bytes):
    return input.decode('utf-8')


# function for RNG
# parameter: the length of wanted random number (in bytes)
# returns: bytes of the generated number
def get_random(len : int):
    func = tpm_api_library.GetRandom
    func.argtypes = [ctypes.POINTER(ctypes.c_uint8), ctypes.c_uint32]
    func.restype = ctypes.c_int
    
    # define buffer to be passed in C function
    buffer = (ctypes.c_uint8 * len)()

    # call function
    rc = func(buffer, len)
    if(rc == 0):    # Success
        return bytes(buffer)
    else:
        return None


# function that stores given bytes to TPM NV storage
# returns: True on success, False on failure
def store_TPM_nv(data : bytes):
    func = tpm_api_library.StoreNV
    func.argtypes = [ctypes.POINTER(ctypes.c_uint8), ctypes.c_uint32]
    func.restype = ctypes.c_int

    data_size = len(data)

    # declare pointers/casts for function inputs
    data_pointer = ctypes.cast(data, ctypes.POINTER(ctypes.c_uint8))
    data_size_c_uint32 = ctypes.c_uint32(data_size)

    # call function
    rc = func(data_pointer, data_size_c_uint32)
    if(rc == 0):    # Success
        return True
    else:
        return False
    

# function that reads bytes from TPM NV storage
# returns: bytes stored in TPM NV storage on succes, None on failure
def read_TPM_nv():
    func = tpm_api_library.ReadNV
    func.argtypes = [ctypes.POINTER(ctypes.c_uint8), ctypes.POINTER(ctypes.c_uint32)]
    func.restype = ctypes.c_int

    # define buffer to be passed in C function
    data = (ctypes.c_uint8 * MAX_NV_STORAGE_SIZE_BYTES)()
    data_size = ctypes.c_uint32(MAX_NV_STORAGE_SIZE_BYTES)

    # call function
    rc = func(data, ctypes.byref(data_size))
    if(rc == 0):    # Success
        return bytes(data)
    else:
        return None
    

# function that deletes the data stored in TPM NV storage
# returns: True on success, False on failure
def delete_TPM_nv():
    func = tpm_api_library.DeleteNV
    func.restype = ctypes.c_int

    # call function
    rc = func
    if(rc == 0):    # Success
        return True
    else:
        return False