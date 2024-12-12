# Imported packages
import socket
import sys
import os
from concurrent.futures import ThreadPoolExecutor
from Crypto import keys, aes_encrypt, decompose_byte

# File directory
sys.path.append(os.path.dirname(os.path.abspath(__file__)))
file_path = os.path.join(os.path.dirname(__file__), "risk.bmp")

# Constants
HOST = '0.0.0.0'  # Listen on all interfaces
PORT = 5555       # Port number
TIMEOUT = 600     # 10 minutes (in seconds)
MAX_THREADS = 10  # Maximum number of threads in the pool
ENCRYPTED_STRING = "The quick brown fox jumps over the lazy dog."  # Encrypted message

# Convert keys from hexadecimal to byte values
keys = {key: bytes.fromhex(format(value, 'x')) for key, value in keys.items()}

# Prepare an encrypted packet using the specified data and crumb
def prepare_packet(data, crumb):
    encryption_key = keys.get(crumb)
    if not encryption_key:
        print(f"[WARNING] No encryption key available for crumb: {crumb}")
        return None
    return aes_encrypt(data, encryption_key)

# Function to handle client connection
def handle_client(conn, addr):
    conn.settimeout(TIMEOUT)
    print(f"[INFO] Connection from {addr} established.")
    try:
        # Load file and decompose it into crumbs
        with open(file_path, "rb") as file:
            crumbs = [crumb for byte in file.read() for crumb in decompose_byte(byte)]

        # Print total number of crumbs to send and notifies the client
        total_crumbs = len(crumbs)
        print(f"[INFO] Preparing to send {total_crumbs} crumbs to {addr}.")
        conn.sendall(str(total_crumbs).encode())

        # Close the server if client is not ready
        client_ready = conn.recv(1024).decode('utf-8')
        if client_ready != "READY":
            print(f"[ERROR] Client {addr} is not ready. Closing connection.")
            return

        # Track when to print updates on decryption progress
        progress_milestone = 0

        # Transmit crumbs to the client
        for crumb_index, crumb in enumerate(crumbs):
            encrypted_packet = prepare_packet(ENCRYPTED_STRING, crumb)
            if not encrypted_packet:
                continue

            # Track acknowledgements from the server
            ack_received = False
            while not ack_received:
                conn.sendall(encrypted_packet)
                try:
                    response = conn.recv(1024).decode('utf-8')
                    # Track percentage based on number of crumbs acknowledged
                    if response == f"ACK:{crumb_index}":
                        progress_percentage = ((crumb_index + 1) / total_crumbs) * 100
                        if progress_percentage >= progress_milestone + 10:
                            progress_milestone += 10
                            print(f"[INFO] Transmission progress: {progress_milestone}% completed.")
                        ack_received = True
                    # Track unacknowledged crumbs
                    elif response == "NACK":
                        print(f"[WARNING] Crumb {crumb_index} rejected by client. Retrying...")
                except socket.timeout:
                    print(f"[WARNING] Timeout while awaiting acknowledgment for crumb {crumb_index}. Retrying...")

        # End signal
        conn.sendall(b"END")
        print(f"[INFO] Successfully transmitted all crumbs to {addr}.")

    # Error handling
    except Exception as error:
        print(f"[ERROR] Communication error with {addr}: {error}")
    finally:
        conn.close()
        print(f"[INFO] Connection with {addr} closed.")

# Main server function
def start_server():
    print(f"[INFO] Starting server at {HOST}:{PORT}.")
    with ThreadPoolExecutor(max_workers=MAX_THREADS) as executor:
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as server_socket:
            server_socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            server_socket.bind((HOST, PORT))
            server_socket.listen()
            print(f"[INFO] Server listening on {PORT}.")

            try:
                while True:
                    # Accept connection to client
                    conn, addr = server_socket.accept()
                    print(f"[INFO] Accepted connection from {addr}.")
                    executor.submit(handle_client, conn, addr)
            except KeyboardInterrupt:
                print("[INFO] Server shutting down gracefully.")

# Catches the main thread
if __name__ == "__main__":
    start_server()
