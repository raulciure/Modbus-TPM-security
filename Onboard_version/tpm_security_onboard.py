import ctypes


MAX_RSA_PUB_KEY_BYTES = 512

tpm_api_library = ctypes.CDLL("/home/raul/Desktop/Packets_security/tpm_api.so")


def string_to_bytes(input : str):
    #return bytes(input, 'utf-8')
    return input.encode('utf-8')


def bytes_to_string(input : bytes):
    return input.decode('utf-8')


# function for RSA key gen
def RSA_key_gen(output_file : str):
    func = tpm_api_library.GenerateRsaKey
    func.argtypes = [ctypes.c_char_p, ctypes.POINTER(ctypes.c_uint8), ctypes.POINTER(ctypes.c_uint32)]
    func.restype = ctypes.c_int

    # define buffers to be passed in C function
    key_pub_buffer = (ctypes.c_uint8 * MAX_RSA_PUB_KEY_BYTES)()
    key_pub_buffer_size = ctypes.c_uint32(MAX_RSA_PUB_KEY_BYTES)

    # call function
    rc = func(string_to_bytes(output_file), key_pub_buffer, ctypes.byref(key_pub_buffer_size))
    if(rc == 0):
        # convert key to bytes type
        return (rc, bytes(key_pub_buffer), key_pub_buffer_size.value)
    else:
        # print("Error generating RSA key!")
        return None
    

# function for RSA key gen that returns both public & private keys
def RSA_key_gen2(output_file : str):
    func = tpm_api_library.GenerateRsaKey2
    func.argtypes = [ctypes.c_char_p, ctypes.POINTER(ctypes.c_uint8), ctypes.POINTER(ctypes.c_uint32), ctypes.POINTER(ctypes.c_uint8), ctypes.POINTER(ctypes.c_uint32)]
    func.restype = ctypes.c_int

    # define buffers to be passed in C function
    key_pub_buffer = (ctypes.c_uint8 * MAX_RSA_PUB_KEY_BYTES)()
    key_pub_buffer_size = ctypes.c_uint32(MAX_RSA_PUB_KEY_BYTES)
    key_priv_buffer = (ctypes.c_uint8 * MAX_RSA_PUB_KEY_BYTES)()
    key_priv_buffer_size = ctypes.c_uint32(MAX_RSA_PUB_KEY_BYTES)

    # call function
    rc = func(string_to_bytes(output_file), key_pub_buffer, ctypes.byref(key_pub_buffer_size), key_priv_buffer, ctypes.byref(key_priv_buffer_size))
    if(rc == 0):
        # convert key to bytes type
        return (rc, bytes(key_pub_buffer), key_pub_buffer_size.value, bytes(key_priv_buffer), key_priv_buffer_size.value)
    else:
        # print("Error generating RSA key!")
        return None


# function for RSA key load
def RSA_key_load(input_file):
    func = tpm_api_library.LoadRsaKey
    func.argtypes = ctypes.c_char_p
    func.restype = ctypes.c_int

    rc = func(string_to_bytes(input_file))
    if(rc == 0):
        return rc
    else:
        print("Error loading RSA key!")
        return None


# function for RSA encryption
def RSA_encrypt(key_buffer : bytes, key_buffer_size : int, msg : bytes, msg_size : int):
    func = tpm_api_library.RsaEncrypt
    func.argtypes = [ctypes.POINTER(ctypes.c_uint8), ctypes.c_uint32, ctypes.POINTER(ctypes.c_uint8), ctypes.c_int, ctypes.POINTER(ctypes.c_uint8), ctypes.POINTER(ctypes.c_int)]
    func.restype = ctypes.c_int

    # declare pointers/casts for function inputs
    key_buffer_pointer = ctypes.cast(key_buffer, ctypes.POINTER(ctypes.c_uint8))
    key_buffer_size_c_uint32 = ctypes.c_uint32(key_buffer_size)
    msg_pointer = ctypes.cast(msg, ctypes.POINTER(ctypes.c_uint8))
    msg_size_c_int = ctypes.c_int(msg_size)

    # define buffer to be passed in C function
    output = (ctypes.c_uint8 * MAX_RSA_PUB_KEY_BYTES)()
    output_size = ctypes.c_int(MAX_RSA_PUB_KEY_BYTES)

    # call function
    rc = func(key_buffer_pointer, key_buffer_size_c_uint32, msg_pointer, msg_size_c_int, output, ctypes.byref(output_size))
    if(rc == 0):    # Success
        return (bytes(output), output_size.value)
    else:
        # print("Error encrypting message RSA!")
        return None


# function for RSA decryption
def RSA_decrypt(key_file : str, input : bytes, input_size : int):
    func = tpm_api_library.RsaDecrypt
    func.argtypes = [ctypes.c_char_p, ctypes.POINTER(ctypes.c_uint8), ctypes.c_int, ctypes.POINTER(ctypes.c_uint8), ctypes.POINTER(ctypes.c_int)]
    func.restype = ctypes.c_int

    # declare pointers/casts for function inputs
    input_pointer = ctypes.cast(input, ctypes.POINTER(ctypes.c_uint8))
    input_size_c_int = ctypes.c_int(input_size)

    # define buffer to be passed in C function
    msg = (ctypes.c_uint8 * MAX_RSA_PUB_KEY_BYTES)()
    msg_size = ctypes.c_int(MAX_RSA_PUB_KEY_BYTES)

    # call function
    rc = func(string_to_bytes(key_file), input_pointer, input_size_c_int, msg, ctypes.byref(msg_size))
    if(rc == 0):    # Success
        return (bytes(msg), msg_size.value)
    else:
        # print("Error decrypting message RSA!")
        return None


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
        # print("Error generating random number!")
        return None