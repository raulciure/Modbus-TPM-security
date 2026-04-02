import socket
import threading
import parse_args
import utils
from key_exchange import key_exchange_routine, SOCKET_RECEIVE_SIZE
from security import *
from Perf_test import latency_test
from time import sleep, time


SOCKET_TIMEOUT = 2      # Socket timeout interval - in seconds
SOCKET_RESET_MESSAGE = b'\x01\x01\x01\x01'

REKEY_TIME = 600        # Time interval between rekeying operations (key session time) - in seconds

REKEY_NONE = 0x00
REKEY_INIT = 0x01
REKEY_REPLY = 0x02
REKEY_SWITCH = 0x03
REKEY_SWITCH_ACK = 0x04
REKEY_FAIL = 0x05

rec_rekey_flag : int    # Received rekey flag (received from peer)
sen_rekey_flag : int    # Sent rekey flag (sent to peer)
rekey_revert_flag = False    # Flag indicating whether it's necesary to revert to old sym_key due to rekey failure

ecc_pub_key_peer = None
ecc_key_own = None

old_sym_key = None
new_sym_key = None

rekey_switch_time : int


def split_rekey_data(comb_data : bytes):
    rekey_flag = comb_data[0]

    # try:
    if rekey_flag == REKEY_INIT or rekey_flag == REKEY_REPLY:
        orig_data = (comb_data[1:])[:-32]    # Slice original data by removing first byte (REKEY field) and last 32 bytes (ECC_public_key)
        ecc_pub_key = comb_data[-32:]        # Get the ECC_pub_key by extracting the last 32 bytes from data
        return (rekey_flag, orig_data, ecc_pub_key)
    elif rekey_flag == REKEY_SWITCH or rekey_flag == REKEY_NONE or rekey_flag == REKEY_SWITCH_ACK:
        orig_data = comb_data[1:]    # Slice original data by removing first byte (REKEY field)
        return (rekey_flag, orig_data, None)
    else:
        raise ValueError
    # except ValueError:
    #     print("*** REKEY field has wrong value! ***")
    #     return None


def combine_rekey_data(rekey_flag : int, data : bytes, ecc_pub_key_own : bytes | None):
    if ecc_pub_key_own is None:
        ecc_pub_key_own = b""
    
    if rekey_flag == REKEY_INIT or rekey_flag == REKEY_REPLY:
        return rekey_flag.to_bytes() + data + ecc_pub_key_own
    # elif rekey_flag == REKEY_SWITCH or rekey_flag == REKEY_NONE or rekey_flag == REKEY_SWITCH_ACK:
    return rekey_flag.to_bytes() + data


def rekey_sender(current_sym_key : bytes, data : bytes):
    global rec_rekey_flag, sen_rekey_flag, rekey_revert_flag, rekey_switch_time
    global ecc_key_own, ecc_pub_key_peer, old_sym_key, new_sym_key

    if rec_rekey_flag == REKEY_NONE:    # If received flag is none (0, i.e. normal operation), check if rekey time has passed
        if int(time()) - rekey_switch_time >= REKEY_TIME:
            sen_rekey_flag = REKEY_INIT
            ecc_key_own = ECC_key_gen()
        else:
            sen_rekey_flag = REKEY_NONE
    elif rec_rekey_flag == REKEY_INIT:
        sen_rekey_flag = REKEY_REPLY
        ecc_key_own = ECC_key_gen()
    elif rec_rekey_flag == REKEY_REPLY:
        if ecc_key_own is not None and ecc_pub_key_peer is not None:
            sen_rekey_flag = REKEY_SWITCH
            new_sym_key = ECDHE_key_agreement(ecc_key_own, ECC_public_key_import(ecc_pub_key_peer))
        else:
            sen_rekey_flag = REKEY_FAIL
    elif rec_rekey_flag == REKEY_SWITCH:
        if new_sym_key is bytes:
            old_sym_key = current_sym_key
            current_sym_key = new_sym_key
            sen_rekey_flag = REKEY_SWITCH_ACK
        else:
            rekey_revert_flag = True
            sen_rekey_flag = REKEY_FAIL
    elif rec_rekey_flag == REKEY_SWITCH_ACK:
        rekey_switch_time = int(time())     # Set rekey time to current time
        sen_rekey_flag = REKEY_NONE
        old_sym_key = None
        new_sym_key = None
        ecc_key_own = ecc_pub_key_peer = None
        print("\t* New key ECDH key exchange performed! *")
    elif rec_rekey_flag == REKEY_FAIL:
        sen_rekey_flag = REKEY_NONE
        if rekey_revert_flag == True and old_sym_key is not None:
            current_sym_key = old_sym_key
        rekey_revert_flag = False
    else:
        print("\t*** rec_key_flag not within specified range! ***")

    comb_data = combine_rekey_data(sen_rekey_flag, data, ECC_key_export(ecc_key_own.public_key()) if (ecc_key_own is not None and sen_rekey_flag in (REKEY_INIT, REKEY_REPLY)) else None)

    return (current_sym_key, comb_data)


def rekey_receiver(current_sym_key : bytes, comb_data : bytes):
    global rec_rekey_flag, ecc_pub_key_peer

    if rec_rekey_flag == REKEY_SWITCH:
        if new_sym_key is bytes:
            current_sym_key = new_sym_key

    (rec_rekey_flag, data, ecc_pub_key_peer) = split_rekey_data(comb_data)

    return (current_sym_key, data)