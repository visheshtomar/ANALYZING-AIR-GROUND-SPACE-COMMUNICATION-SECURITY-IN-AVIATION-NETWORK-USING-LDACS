import socket

# IPs and Ports
sender_ip = "127.0.0.1"
sender_port = 5003
receiver_ip = "127.0.0.1"
receiver_port = 5002
interceptor_port = 5004  # The port on which the interceptor listens

# Create a UDP socket for the interceptor
sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
sock.bind((sender_ip, interceptor_port))

print(f"Interceptor listening on {sender_ip}:{interceptor_port}")

def tamper_packet(data):
    # Tamper with the packet data here if needed
    # For this example, let's add a simple tampering: appending "TAMPERED" to the data
    return data + b"TAMPERED"

while True:
    data, addr = sock.recvfrom(4096)
    print(f"Received packet from {addr}: {data.hex()}")

    # Call the tampering function (or don't, if you just want to forward without tampering)
    tampered_data = tamper_packet(data)

    # Forward the tampered packet to the receiver
    sock.sendto(tampered_data, (receiver_ip, receiver_port))
    print(f"Forwarded tampered packet to {receiver_ip}:{receiver_port}")
