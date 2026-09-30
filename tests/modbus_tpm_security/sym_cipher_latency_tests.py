import random
from src.modbus_tpm_security.sym_cipher import *
from src.modbus_tpm_security.perf_measure.latency_measure import LatencyMeter
from types import SimpleNamespace


TIMESTAMP_OPERATION = True
MSG_SIZE = 12
TEST_RUNS = 20

cipher_obj = SymCipher_GCM(None, random.randbytes(32))

latency_meter_enc = LatencyMeter()
latency_meter_dec = LatencyMeter()

if TIMESTAMP_OPERATION is True:
    args = None
else:
    args = SimpleNamespace(set_replay_resistance = "seq-num",
                       disable_rekeying = True,
                       disable_replay_resistance = None,
                       v = None,
                       vv = None,
                       vvv = True,
                       is_client = True)

for i in range(TEST_RUNS):
    message = random.randbytes(MSG_SIZE)

    enc_message = latency_meter_enc.measure_latency(lambda: cipher_obj.encrypt_and_digest(message))
    dec_message = latency_meter_dec.measure_latency(lambda: cipher_obj.decrypt_and_verify(enc_message))

print("enc_latency:\t", latency_meter_enc.get_average_latency())
print("average runs:\t", latency_meter_enc.get_average_runs())
print()
print("dec_latency:\t", latency_meter_dec.get_average_latency())
print("average runs:\t", latency_meter_dec.get_average_runs())
    