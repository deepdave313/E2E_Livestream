import socket
import cv2
import numpy as np
import tkinter as tk
from threading import Thread
from Crypto.Cipher import AES
from Crypto.PublicKey import RSA
from Crypto.Cipher import PKCS1_OAEP
from Crypto.Random import get_random_bytes
import pickle

# Global variables
server_socket = None
conn = None
streaming = False

# Function to start the livestream
def start_stream():
    global server_socket, conn, streaming

    SERVER_IP = "0.0.0.0"
    PORT = 5000

    server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server_socket.bind((SERVER_IP, PORT))
    server_socket.listen(1)
    print("[*] Waiting for connection...")
    conn, addr = server_socket.accept()
    print(f"[*] Connected to {addr}")

    # Generate RSA Key Pair
    rsa_key = RSA.generate(2048)
    private_key = rsa_key.export_key()
    public_key = rsa_key.publickey().export_key()

    # Send Public Key to Receiver
    conn.send(public_key)

    # Receive Encrypted AES Key
    encrypted_aes_key = conn.recv(256)

    # Decrypt AES Key using Private Key
    cipher_rsa = PKCS1_OAEP.new(RSA.import_key(private_key))
    aes_key = cipher_rsa.decrypt(encrypted_aes_key)

    print("[*] AES Key successfully exchanged!")

    # Start video capture
    cap = cv2.VideoCapture(0)
    streaming = True

    try:
        while streaming and cap.isOpened():
            ret, frame = cap.read()
            if not ret:
                break

            # Convert frame to bytes
            _, buffer = cv2.imencode('.jpg', frame)
            frame_bytes = buffer.tobytes()

            # Encrypt frame
            cipher_aes = AES.new(aes_key, AES.MODE_EAX)
            nonce = cipher_aes.nonce
            encrypted_frame, tag = cipher_aes.encrypt_and_digest(frame_bytes)

            # Send nonce, tag, and encrypted frame
            data_packet = pickle.dumps((nonce, tag, encrypted_frame))
            try:
                conn.send(len(data_packet).to_bytes(4, 'big'))  # Send length first
                conn.sendall(data_packet)  # Send full encrypted packet
            except (ConnectionResetError, BrokenPipeError):
                print("[!] Connection lost. Stopping stream.")
                break

            cv2.imshow("Sending Video", frame)
            if cv2.waitKey(1) & 0xFF == ord('q'):
                break

    except Exception as e:
        print(f"[!] Error: {e}")

    finally:
        cap.release()
        conn.close()
        server_socket.close()
        cv2.destroyAllWindows()
        print("[*] Stream stopped.")

# Function to stop the stream
def stop_stream():
    global streaming
    streaming = False
    print("[*] Stopping stream...")
    if server_socket:
        server_socket.close()
    root.quit()

# Function to start stream in a separate thread
def start_stream_thread():
    thread = Thread(target=start_stream)
    thread.start()

# UI Setup
root = tk.Tk()
root.title("Encrypted Livestream - Sender")

tk.Button(root, text="Start Call", command=start_stream_thread, bg="green", fg="white", font=("Arial", 14)).pack(pady=10)
tk.Button(root, text="End Call", command=stop_stream, bg="red", fg="white", font=("Arial", 14)).pack(pady=10)

root.mainloop()
