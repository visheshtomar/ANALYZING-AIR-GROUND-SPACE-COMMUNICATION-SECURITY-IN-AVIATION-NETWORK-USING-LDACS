
def diffie_hellman_exchange(p, g, private_key=None):
    import random
    if private_key is None:
        private_key = random.randint(1, p-2)
    public_key = pow(g, private_key, p)
    return public_key, private_key

p = 23  # a prime number
g = 5   # a primitive root modulo p

# Perform DH for sender
sender_public_key, sender_private_key = diffie_hellman_exchange(p, g)
print(f"Sender's Public Key: {sender_public_key}")


import subprocess

# Call the keygen.py script
subprocess.call(["python", "keygen.py"])

from snp import encapsulate
import socket
from snp import SNPFlowControl, decapsulate
from encryption import encryption_key
from authentication import DigitalSignature
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import serialization
import tkinter as tk
from tkinter import messagebox

def alert_popup(message):
    # Create a simple root window
    root = tk.Tk()
    root.withdraw()  # Hide the main window
    messagebox.showinfo("Message Received", message)  # Show alert message box
    root.destroy()  # Destroy the root window

def clear_screen():
    import os
    import platform

    if platform.system() == "Windows":
        os.system('cls')
    else:
        os.system('clear')

receiver_ip = "127.0.0.1"
receiver_port = 5002

sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
sock.bind((receiver_ip, receiver_port))

print(f"Start listening on {receiver_ip}:{receiver_port}")

# Load the private key from file
with open("private_key.pem", "rb") as key_file:
    private_key = serialization.load_pem_private_key(
        key_file.read(),
        password=None,
        backend=default_backend()
    )

# Load the public key from file
with open("public_key.pem", "rb") as key_file:
    public_key = serialization.load_pem_public_key(
        key_file.read(),
        backend=default_backend()
    )

digital_signature = DigitalSignature(private_key, public_key)
flow_control = SNPFlowControl()
encryption_key = encryption_key  # This should be derived or set from somewhere else

receiver_menu_string = """
Please select an option:
1. Have a safe journey
2. Request Accepted
3. Weather is clear
4. Wait for further update
5. Request Accepted (for exit from sender)
Enter your choice: """
while True:
    encapsulated_packet, addr = sock.recvfrom(4096)
    #print("Received SNP Packet:", encapsulated_packet)

    ip_packet = decapsulated_packet = decapsulate(encapsulated_packet, flow_control, digital_signature, encryption_key)
    #if ip_packet is not None:
        #print("Decapsulated Packet:", ip_packet)
    
    received_msg = ip_packet.decode("utf-8")
    alert_popup(received_msg)  # Display the popup alert with the message
    print("")
    print("---------------------------------------------------")
    print("Received Message:", received_msg)
    print("---------------------------------------------------")    
 
    
    print(receiver_menu_string)
    choice = input().strip()
    if choice == "1":
        response = "Have a safe journey"
    elif choice == "2":
        response = "Request Accepted"
    elif choice == "3":
        response = "Weather is clear"
    elif choice == "4":
        response = "Wait for further update"
    elif choice == "5":
        response = "Request Accepted for exit"
        #print("Terminating receiver...")
        #sock.close()
        #exit()
    else:
        print("Invalid choice. Please select a valid option.")
        print(receiver_menu_string)
        choice = input().strip()

    print("ATC Response:", response)
    response_packet = response.encode("utf-8")
    encapsulated_response = encapsulate(response_packet, dest_id=1, source_id=2, sequence_number=1, flags=0, flow_control=flow_control, digital_signature=digital_signature)
    sock.sendto(encapsulated_response, addr)


