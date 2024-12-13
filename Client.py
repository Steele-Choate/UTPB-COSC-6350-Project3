# Imported packages
import socket
import sys
import os
import random
from Crypto import aes_decrypt, keys

# File directory
sys.path.append(os.path.dirname(os.path.abspath(__file__)))

# Constants
SERVER_HOST = '127.0.0.1'
SERVER_PORT = 5555
CLIENT_TIMEOUT = 600
BUFFER_LIMIT = 1024
DECRYPTED_STRING = "The quick brown fox jumps over the lazy dog."
DEBUG = False
EAVESDROPPING_THRESHOLD = 0.25  # Minimum fraction of crumbs successfully decoded after each full transmission

# Convert keys from hexadecimal to byte values
keys = {key: bytes.fromhex(format(value, 'x')) for key, value in keys.items()}

# Report progress
def report_success_rate(successful, total):
    success_rate = (successful / total) * 100
    print(f"[INFO] Decryption Success Rate: {success_rate:.2f}% ({successful}/{total})")

# Recompose byte from crumbs
def recompose_byte(crumbs):
    byte = 0
    for i, crumb in enumerate(crumbs):
        byte |= (crumb << (i * 2))
    return byte

# Write crumbs to file
def write_to_file(crumbs, filename):
    bytes_data = bytearray()
    for i in range(0, len(crumbs), 4):
        crumbs_slice = crumbs[i:i+4]
        if None not in crumbs_slice:  # Ensure all crumbs are decoded
            bytes_data.append(recompose_byte(crumbs_slice))
    with open(filename, 'wb') as f:
        f.write(bytes_data)
    print(f"[INFO] File successfully written to {filename}.")

# Function to send packet acknowledgments to the server
def acknowledge_packet(client_socket, packet_index):
    try:
        client_socket.sendall(f"ACK:{packet_index}".encode('utf-8'))
    except Exception as ack_error:
        print(f"[ERROR] Failed to send ACK for packet {packet_index}: {ack_error}")

# Function to connect to the server and process crumbs
def tcp_client():
    try:
        print("[INFO] Initiating connection to the server...")
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as client_socket:
            client_socket.settimeout(CLIENT_TIMEOUT)
            client_socket.connect((SERVER_HOST, SERVER_PORT))
            print(f"[INFO] Connected to {SERVER_HOST}:{SERVER_PORT}")

            # Receive total number of crumbs
            total_packets = int(client_socket.recv(BUFFER_LIMIT).decode('utf-8'))
            print(f"[INFO] Total packets to process: {total_packets}")
            client_socket.sendall(b"READY")

            # Initialize tracking structures
            crumbs = [None] * total_packets  # List to hold successfully decrypted crumb key IDs
            attempted_keys = {i: set() for i in range(total_packets)}  # Track keys used for each crumb
            all_keys = list(keys.keys())  # Available key IDs

            # Receive crumbs in four cycles
            for cycle in range(1, 5):
                print(f"\n[INFO] Starting decryption cycle {cycle}.")
                for crumb_index in range(total_packets):
                    encrypted_data = client_socket.recv(BUFFER_LIMIT)
                    if not encrypted_data:
                        print("[INFO] Server closed the connection. Exiting.")
                        return
                    if encrypted_data == b"END":
                        print("[INFO] All transmission cycles completed.")
                        break

                    # Skip crumbs already successfully decrypted
                    if crumbs[crumb_index] is not None:
                        acknowledge_packet(client_socket, crumb_index)
                        continue

                    # Find an unused key for this crumb
                    unused_keys = [k for k in all_keys if k not in attempted_keys[crumb_index]]
                    if not unused_keys:
                        # If no keys remain, skip this crumb
                        print(f"[WARNING] All keys exhausted for crumb {crumb_index}.")
                        acknowledge_packet(client_socket, crumb_index)
                        continue

                    # Attempt decryption with an unused key
                    next_key_id = random.choice(unused_keys)
                    attempted_keys[crumb_index].add(next_key_id)
                    next_key = keys[next_key_id]

                    try:
                        decrypted_message = aes_decrypt(encrypted_data, next_key)
                    except ValueError:
                        decrypted_message = None

                    if decrypted_message == DECRYPTED_STRING:
                        crumbs[crumb_index] = next_key_id

                    # Acknowledge receipt of the crumb
                    acknowledge_packet(client_socket, crumb_index)

                # Report progress after each cycle
                successful_decryptions = sum(1 for crumb in crumbs if crumb is not None)
                remaining = total_packets - successful_decryptions
                progress_percentage = (successful_decryptions / total_packets) * 100
                print(f"[INFO] Cycle {cycle} complete: {progress_percentage:.2f}% decrypted "
                      f"({successful_decryptions}/{total_packets}). {remaining} crumbs remaining.")

            # Report final success rate
            successful_decryptions = sum(1 for crumb in crumbs if crumb is not None)
            report_success_rate(successful_decryptions, total_packets)

            # Recompose crumbs and save to file
            write_to_file(crumbs, "output_file.bin")

    except (socket.timeout, ConnectionError) as e:
        print(f"[ERROR] Network error: {e}")
    except Exception as e:
        print(f"[ERROR] Unexpected error: {e}")
    finally:
        print("[INFO] Connection closed.")

# Catches the main thread
if __name__ == "__main__":
    tcp_client()
