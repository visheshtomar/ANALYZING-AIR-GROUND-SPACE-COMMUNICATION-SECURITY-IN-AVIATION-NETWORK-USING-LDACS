import tkinter as tk
from tkinter import messagebox
import socket
import ipaddress
from snp import SNPFlowControl, encapsulate, decapsulate
from authentication import DigitalSignature
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import serialization
from encryption import encryption_key

def diffie_hellman_exchange(p, g, private_key=None):
    import random
    if private_key is None:
        private_key = random.randint(1, p-2)
    public_key = pow(g, private_key, p)
    return public_key, private_key

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

p = 23  # a prime number
g = 5   # a primitive root modulo p

# Perform DH for sender
sender_public_key, sender_private_key = diffie_hellman_exchange(p, g)
print(f"Sender's Public Key: {sender_public_key}")

print("Enter receiver IP address:")
receiver_ip = input()

try:
    ipaddress.ip_address(receiver_ip)
except ValueError:
    print("Invalid IP address")
    exit()

#Change the ip Address here for intercepter
sender_ip = "127.0.0.1"
sender_port = 5003

#commentout the receiver port when intercepter port open
receiver_port = 5002


#intercepter Port
#receiver_port = 5004


sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
sock.bind((sender_ip, sender_port))

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

# Create an instance of the DigitalSignature class using the loaded keys
digital_signature = DigitalSignature(private_key, public_key)
flow_control = SNPFlowControl()

menu_string = """
Please select an option:
1. Ready for takeoff
2. Ready for landing
3. Turning towards left
4. Request to change Direction
5. Request for Current weather
6. Terminate the connection
Enter your choice: """
    

while True:
    clear_screen()
    print(menu_string)
    choice = input().strip()
    if choice == "1":
        message = "Ready for takeoff"
    elif choice == "2":
        message = "Ready for landing"
    elif choice == "3":
        message = "Turning towards left"
    elif choice == "4":
        message = "Request to change Direction"
    elif choice == "5":
        message = "Request for Current weather"
    elif choice == "6":
        message = "Request for termination"
    else:
        print("Invalid choice. Please select a valid option.")
        continue

    if message.lower() == "Request Accepted for exit":
        break

    #alert_popup(message)  # Display the popup alert with the message

    ip_packet = message.encode("utf-8")
    source_id = 1
    dest_id = 2
    sequence_number = 1
    flags = 0

    data_sent = False
    while not data_sent:
        encapsulated_packet = encapsulate(ip_packet, source_id, dest_id, sequence_number, flags, flow_control,
                                          digital_signature)

        if encapsulated_packet is None:
            print("Packet was dropped due to flow control or fragmentation")
        else:
            sock.sendto(encapsulated_packet, (receiver_ip, receiver_port))
            data_sent = True
            
    encapsulated_response, _ = sock.recvfrom(4096)
    decapsulated_response = decapsulate(encapsulated_response, flow_control, digital_signature, encryption_key)
    if decapsulated_response and decapsulated_response.decode("utf-8") == "Request Accepted for exit":
        alert_popup(decapsulated_response)  # Display the popup alert with the message
        print("")
        print("---------------------------------------------------")
        print("Termination approved by receiver. Exiting...")
        print("---------------------------------------------------")
        break

    response_packet = decapsulate(encapsulated_response, flow_control, digital_signature, encryption_key)
    if response_packet is not None:
        alert_popup(response_packet)  # Display the popup alert for the received message
        print("")
        print("---------------------------------------------------")
        print("Received Response:", response_packet.decode("utf-8"))
        print("---------------------------------------------------")

sock.close()
