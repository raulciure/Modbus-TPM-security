import csv
from Crypto.Hash import SHA256


ID_counter = 1
found_flag = False

message = "Hello world!"

message_hash = SHA256.new(message.encode("utf-8"))

print("Message: " + message)
print("Hash: " + message_hash.hexdigest())

# Find how many IDs are already in use
try:
    with open("test.csv", "r", newline="") as test_file:
        reader = csv.reader(test_file, delimiter=":")
        for row in reader:
            if row:
                if row[0] == message_hash.hexdigest():
                    print("Value found: " + row[0] + ":" + row[1])
                    found_flag = True
                    break
                ID_counter += 1
except FileNotFoundError:
    print("File not found. Creating file.")

print("ID_counter = " + str(ID_counter))

if found_flag == False:
    with open("test.csv", "a", newline="") as test_file:
        # Write new entry into peers_file
        writer = csv.writer(test_file, delimiter=":")
        writer.writerow((message_hash.hexdigest(), ID_counter))