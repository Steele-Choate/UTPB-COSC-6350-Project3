# Imported packages
import socket
import sys
import os
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

# Report progress if a milestone is reached
def report_progress(processed, total, last_marker, increment=10):
    current_progress = (processed / total) * 100
    if current_progress >= last_marker + increment:
        print(f"[INFO] Progress: {current_progress:.0f}% completed.")
        return current_progress
    return last_marker

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

            # Print total number of packets
            total_packets = int(client_socket.recv(BUFFER_LIMIT).decode('utf-8'))
            print(f"[INFO] Total packets to process: {total_packets}")
            client_socket.sendall(b"READY")

            # Track progress and maintain lists
            crumbs = [None] * total_packets  # List to hold decoded crumbs
            attempted_keys = [[] for _ in range(total_packets)]  # List of lists for attempted keys per crumb
            processed_packets = 0
            last_progress_marker = 0
            previous_progress = 0

            while True:
                encrypted_data = client_socket.recv(BUFFER_LIMIT)
                if not encrypted_data:
                    print("[INFO] Server closed the connection. Exiting.")
                    break
                if encrypted_data == b"END":
                    print(f"[INFO] All {total_packets} packets received.")
                    break

                # Process crumbs that haven't been decoded
                crumb_index = processed_packets

                if crumbs[crumb_index] is not None:
                    # Skip if already decoded
                    acknowledge_packet(client_socket, crumb_index)
                    continue

                decrypted_message = None
                selected_key = None

                # Attempt decryption using a random untried key
                for key_id, key in keys.items():
                    if key_id not in attempted_keys[crumb_index]:
                        try:
                            decrypted_message = aes_decrypt(encrypted_data, key)
                            if decrypted_message == DECRYPTED_STRING:
                                selected_key = key_id
                                break
                        except ValueError:
                            attempted_keys[crumb_index].append(key_id)

                # If successfully decrypted, mark crumb and acknowledge
                if decrypted_message == DECRYPTED_STRING:
                    crumbs[crumb_index] = selected_key  # Save the corresponding key ID
                    processed_packets += 1
                    acknowledge_packet(client_socket, crumb_index)
                    last_progress_marker = report_progress(processed_packets, total_packets, last_progress_marker)
                else:
                    # If no key works, notify server with NACK
                    client_socket.sendall(b"NACK")
                    if DEBUG:
                        print(f"[DEBUG] Decryption failed for crumb {crumb_index}. Keys tried: {attempted_keys[crumb_index]}")

                # Check for eavesdropping after every full file transmission
                if crumb_index + 1 == total_packets:
                    current_progress = processed_packets / total_packets
                    if current_progress - previous_progress < EAVESDROPPING_THRESHOLD:
                        print("[ALERT] Potential eavesdropping detected! Terminating connection.")
                        client_socket.close()
                        return
                    previous_progress = current_progress

            # Recompose crumbs and save to file
            write_to_file(crumbs, "output_file.bin")

    # Error handling
    except (socket.timeout, ConnectionError) as e:
        print(f"[ERROR] Network error: {e}")
    except Exception as e:
        print(f"[ERROR] Unexpected error: {e}")
    finally:
        print("[INFO] Connection closed.")

# Catches the main thread
if __name__ == "__main__":
    tcp_client()
