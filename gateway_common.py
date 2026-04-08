from time import time
from security import *


SOCKET_TIMEOUT = 2      # Socket timeout interval - in seconds
SOCKET_RESET_MESSAGE = b'\x01\x01\x01\x01'

REKEY_TIME = 600        # Time interval between rekeying operations (key session time) - in seconds

REKEY_NONE = 0x00
REKEY_INIT = 0x01
REKEY_REPLY = 0x02
REKEY_SWITCH = 0x03
REKEY_SWITCH_ACK = 0x04
REKEY_FAIL = 0x05

rec_rekey_flag = REKEY_NONE         # Received rekey flag (received from peer)
sen_rekey_flag = REKEY_NONE         # Sent rekey flag (sent to peer)
rekey_revert_flag = False           # Flag indicating whether it's necesary to revert to old sym_key due to rekey failure
is_rekey_initiator : bool | None    # Flag indicating whether the device is the one that initiated the rekeying process
delayed_rekey_flag = False    # Flag indicating whether change to new key should happen after one cycle or in this moment (different for initiator and replier)

ecc_pub_key_peer = None
ecc_key_own = None

old_sym_key = None
new_sym_key = None
current_sym_key = None

rekey_switch_time : int


# Split (deserialise) combined data in a tuple
# returns (rekey_flag, data, ecc_pub_key | None)
# throws ValueError if rekey_flag value is not known
def split_rekey_data(comb_data : bytes):
    rekey_flag = comb_data[0]

    if rekey_flag == REKEY_INIT or rekey_flag == REKEY_REPLY:
        data = (comb_data[1:])[:-32]    # Slice original data by removing first byte (REKEY field) and last 32 bytes (ECC_public_key)
        ecc_pub_key = comb_data[-32:]        # Get the ECC_pub_key by extracting the last 32 bytes from data
        return (rekey_flag, data, ecc_pub_key)
    elif rekey_flag in (REKEY_NONE, REKEY_SWITCH, REKEY_SWITCH_ACK, REKEY_FAIL):
        data = comb_data[1:]    # Slice original data by removing first byte (REKEY field)
        return (rekey_flag, data, None)
    else:
        raise ValueError


# Combine (serialise) rekey_flag, data, and ecc_pub_key_own to bytes for transmission over network
# returns bytes representing combined sequential bytes of rekey_flag, data, ecc_pub_key_own
def combine_rekey_data(rekey_flag : int, data : bytes, ecc_pub_key_own : bytes | None = None):  
    if rekey_flag == REKEY_INIT or rekey_flag == REKEY_REPLY:
        if ecc_pub_key_own is not None:
            return rekey_flag.to_bytes() + data + ecc_pub_key_own
        else:
            print("*** ecc_pub_key_own is None when it should have been bytes! ***")
    return rekey_flag.to_bytes() + data


# Process received rekey plain text and set global flags and variables accordingly
# returns (current_sym_key, data)
def rekey_receiver(current_sym_key_arg : bytes, comb_data : bytes):
    global rec_rekey_flag, ecc_pub_key_peer, new_sym_key

    try:
        split_result = split_rekey_data(comb_data)
        if split_result[2] is not None:
            (rec_rekey_flag, data, ecc_pub_key_peer) = split_result
        else:
            (rec_rekey_flag, data) = split_result[:2]

        rekey_set_flags(current_sym_key_arg)

        return data
    except ValueError:
        raise ValueError


# Process to-send rekey plain text and set global flags and variables accordingly
# returns (current_sym_key, comb_data)
def rekey_sender(data : bytes):
    global sen_rekey_flag
    global ecc_key_own

    comb_data = combine_rekey_data(sen_rekey_flag, data, ECC_key_export(ecc_key_own.public_key()) if (ecc_key_own is not None and sen_rekey_flag in (REKEY_INIT, REKEY_REPLY)) else None)

    return comb_data


def rekey_set_flags(sym_key_arg : bytes):
    global rec_rekey_flag, sen_rekey_flag
    global rekey_revert_flag, rekey_switch_time
    global ecc_key_own, ecc_pub_key_peer, old_sym_key, new_sym_key, current_sym_key
    global is_rekey_initiator, delayed_rekey_flag


    def gen_error():
        print("\t*** rec_key_flag not within specified range! ***")
        raise ValueError
    

    current_sym_key = old_sym_key = sym_key_arg
    
    if rec_rekey_flag == REKEY_NONE:    # If received flag is none (0, i.e. normal operation), check if rekey time has passed
        if int(time()) - rekey_switch_time >= REKEY_TIME:
            is_rekey_initiator = True
            sen_rekey_flag = REKEY_INIT
            ecc_key_own = ECC_key_gen()
        else:
            sen_rekey_flag = REKEY_NONE
            new_sym_key = old_sym_key = None
    elif rec_rekey_flag == REKEY_INIT:
        is_rekey_initiator = False
        sen_rekey_flag = REKEY_REPLY
        ecc_key_own = ECC_key_gen()

        if ecc_pub_key_peer is not None:
            new_sym_key = ECDHE_key_agreement(ecc_key_own, ECC_public_key_import(ecc_pub_key_peer))
            if new_sym_key is not None:
                old_sym_key = current_sym_key
                current_sym_key = new_sym_key
                delayed_rekey_flag = True
            else:
                sen_rekey_flag = REKEY_FAIL
        else:
            sen_rekey_flag = REKEY_FAIL
    else:
        if is_rekey_initiator is not None:
            if rekey_revert_flag == True:
                sen_rekey_flag = REKEY_NONE
                new_sym_key = old_sym_key = None
                ecc_pub_key_peer = ecc_key_own = None
                if old_sym_key is not None:
                    current_sym_key = old_sym_key
                return

            # Process flags differently based on device function (initiator or replier)
            if is_rekey_initiator == True:  # If device is initiator
                if rec_rekey_flag == REKEY_REPLY:
                    if ecc_key_own is not None and ecc_pub_key_peer is not None:
                        sen_rekey_flag = REKEY_SWITCH

                        new_sym_key = ECDHE_key_agreement(ecc_key_own, ECC_public_key_import(ecc_pub_key_peer))
                        if new_sym_key is not None:
                            old_sym_key = current_sym_key
                            current_sym_key = new_sym_key
                        else:
                            sen_rekey_flag = REKEY_FAIL
                    else:
                        sen_rekey_flag = REKEY_FAIL
                elif rec_rekey_flag == REKEY_SWITCH_ACK:
                    rekey_switch_time = int(time())     # Set rekey time to current time
                    sen_rekey_flag = REKEY_NONE
                    ecc_key_own = ecc_pub_key_peer = None
                    print("\t* New ECDH key exchange performed! *")
                    is_rekey_initiator = None
                elif rec_rekey_flag == REKEY_FAIL:
                    sen_rekey_flag = REKEY_NONE
                    if old_sym_key is not None:
                        current_sym_key = old_sym_key
                else:
                    gen_error()
            
            else:                           # If device is replier
                if rec_rekey_flag == REKEY_SWITCH:
                    if new_sym_key is not None:
                        old_sym_key = current_sym_key
                        current_sym_key = new_sym_key
                        sen_rekey_flag = REKEY_SWITCH_ACK
                        delayed_rekey_flag = True

                        rekey_switch_time = int(time())     # Set rekey time to current time
                        ecc_key_own = ecc_pub_key_peer = None
                        print("\t* New ECDH key exchange performed! *")
                        is_rekey_initiator = None
                    else:
                        sen_rekey_flag = REKEY_FAIL
                        if old_sym_key is not None:
                            current_sym_key = old_sym_key
                elif rec_rekey_flag == REKEY_FAIL:
                    sen_rekey_flag = REKEY_NONE
                    new_sym_key = old_sym_key = None
                    ecc_pub_key_peer = ecc_key_own = None
                    if old_sym_key is not None:
                        current_sym_key = old_sym_key
                else:
                    gen_error()


def rekey_get_new_key():
    global delayed_rekey_flag

    if delayed_rekey_flag == True:
        delayed_rekey_flag = False
        return old_sym_key
    
    return current_sym_key