import pickle

msg_tuple = (b'ABCD', bytes(32), b'EFGHIJ')

print("msg_tuple = ", msg_tuple)

msg_data = pickle.dumps(msg_tuple)

print("msg_data = ", msg_data)

reconstr_tuple = pickle.loads(msg_data)

print("reconstr_tuple = ", reconstr_tuple)
    