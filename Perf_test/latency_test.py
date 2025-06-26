import datetime
from time import perf_counter


key_exchange_latency = 0
encrpyt_average_latency = 0
encrypt_average_counter = 0
decrypt_average_latency = 0
decrypt_average_counter = 0

# Function for exporting measured data to file
def export_to_file():
    with open("latency_output.txt", "a", newline="") as output_file:
        output_file.write("#############################################\n")
        output_file.write(datetime.datetime.now().isoformat(' ', 'seconds') + "\n")
        output_file.write(f"Key exchange latency:     \t{key_exchange_latency}\n")
        output_file.write(f"Encrypt & digest latency: \t{encrpyt_average_latency}\n")
        output_file.write(f"Decrypt & verify latency: \t{decrypt_average_latency}\n\n")

# Function for adding a new value to an existing average of "size" numbers
def add_to_average(average, size, add_value):
    if(average == 0):
        average = add_value
    else:
        average = average + ((add_value - average) / (size + 1))
    size += 1
    return [average, size]
