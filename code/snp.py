import struct
from scapy.packet import Packet
from scapy.fields import *
import time
import zlib
from authentication import DigitalSignature, private_key, public_key
from encryption import encrypt, decrypt
from encryption import iv, encryption_key
from cryptography.hazmat.primitives.asymmetric import rsa
import tkinter as tk
from tkinter import messagebox

# SNP Header class definition
class SNPHeader(Packet):
    fields_desc = [
        ByteField("type", 1),
        ShortField("src_id", 0),
        ShortField("dst_id", 0),
        ShortField("sequence_number", 0),
        ByteField("priority", 0),
        IntField("timestamp", 0),
        FlagsField("flags", 0, 8, ["MF", "LF"]),
        IntField("fragment_offset", 0),
        IntField("checksum", 0),
        StrLenField("data", "", length_from=lambda pkt: pkt.get_data_length()),
        ByteField("qos_priority", 0),
        ByteField("qos_latency", 0),
        ByteEnumField("control_type", 1, {1: "Resource Request"}),
        ByteField("mgmt_type", 0),
        MACField("mgmt_target", 0),
        StrFixedLenField("signature", 0, 16),
        StrFixedLenField("iv", 0, 16),  # New field for IV
        ByteField("fragmented", 0),  # New field for fragmentation flag
        IntField("fragment_length", 0),  # New field for fragment length
    ]

    def calculate_checksum(self):
        # Exclude the checksum field itself from the data used for checksum calculation
        data = struct.pack('!BHHHBIIB', int(self.type), int(self.src_id), int(self.dst_id), int(self.sequence_number),
                           int(self.priority), int(self.timestamp), int(self.flags),
                           int(self.fragment_offset)) + self.data
        self.checksum = zlib.crc32(data) & 0xFFFFFFFF  # Use bitwise AND to ensure the checksum is a 32-bit integer

    def validate_checksum(self):
        # Exclude the checksum field itself from the data used for checksum calculation
        data = struct.pack(
            '!BHHHBIIB',
            int(self.type),
            int(self.src_id),
            int(self.dst_id),
            int(self.sequence_number),
            int(self.priority),
            int(self.timestamp),
            int(self.flags),
            int(self.fragment_offset)
        ) + self.data
        return self.checksum == (zlib.crc32(data) & 0xFFFFFFFF)  # Use bitwise AND for comparison as well

    def get_data_length(self):
        return len(self.data)


# Encapsulation function with Flow Control
class SNPFlowControl:
    def __init__(self):
        self.window_size = 10
        self.unacknowledged_packets = []
        self.sent_sequence_number = 0
        self.timeout_duration = 5

    def can_send(self):
        return len(self.unacknowledged_packets) < self.window_size

    def send_packet(self, packet):
        if self.can_send():
            self.sent_sequence_number += 1
            packet.sequence_number = self.sent_sequence_number
            packet.sent_time = time.time()
            self.unacknowledged_packets.append(packet)
            return True
        return False

    def handle_ack(self, sequence_number):
        self.unacknowledged_packets = [packet for packet in self.unacknowledged_packets if packet.sequence_number > sequence_number]
        self.window_size += 1

    def check_timeouts(self):
        current_time = time.time()
        for packet in self.unacknowledged_packets:
            if current_time - packet.sent_time > self.timeout_duration:
                # Retransmit the packet
                packet.sent_time = current_time
                self.send_packet(packet)

def alert_popup():
            # Create a simple root window
            root = tk.Tk()
            root.withdraw()  # Hide the main window
            messagebox.showinfo("Alert", "Invalid Digital Signature")  # Show alert message box
            root.destroy()  # Destroy the root window


verifiable_data = None
def encapsulate(ip_packet, source_id, dest_id, sequence_number, flags, flow_control, digital_signature):
    # Check if we can send a new packet using flow control
    if not flow_control.can_send():
        return None  # Cannot send packet due to flow control constraints

        # Check if fragmentation is required
        # deepcode ignore PythonDeadCode: <please specify a reason of ignoring this>
        max_fragment_size = 100  # Define the maximum fragment size (you can adjust this value)
        if len(ip_packet) > max_fragment_size:
            # Fragment the IP packet
            fragment_offset = 0
            while len(ip_packet) > 0:
                # Create a new SNP header for each fragment
                fragment_header = SNPHeader(
                    type=1,  # Data packet
                    src_id=source_id,
                    dst_id=dest_id,
                    sequence_number=sequence_number,
                    priority=0,
                    timestamp=int(time.time()),
                    flags=flags,
                    fragmented=1,  # Set the fragmented flag
                    fragment_offset=fragment_offset,
                    fragment_length=min(max_fragment_size, len(ip_packet)),
                    signature=0,
                )

                # Get the current fragment and remove it from the original IP packet
                current_fragment = ip_packet[:max_fragment_size]
                ip_packet = ip_packet[max_fragment_size:]

                # Calculate checksum and sign the fragment header
                fragment_header.data = current_fragment
                fragment_header.calculate_checksum()
                fragment_header.signature = digital_signature.sign_packet(bytes(fragment_header))

                # Add the fragment header to the unacknowledged packets list
                if not flow_control.send_packet(fragment_header):
                    return None  # Cannot send packet due to flow control constraints

                fragment_offset += len(current_fragment)

            # Return None to indicate that the original packet was fragmented
            return None

    # Create the SNP header
    header = SNPHeader(
        
        type=1,  # Data packet
        src_id=source_id,
        dst_id=dest_id,
        sequence_number=sequence_number,  # New: Assign sequence number
        priority=0,
        timestamp=int(time.time()),  # New: Use current timestamp
        flags=flags,
        fragment_offset=0,  # New: Initially set to 0, adjust when fragmenting
        iv=iv,
        signature=0  # New: Initially set to 0, will be updated after signing
    )
    # Calculate the checksum
    header.calculate_checksum()

    # Encrypt the IP packet using the random encryption key
    encrypted_ip_packet, header.iv = encrypt(ip_packet, encryption_key)
    
    # Check if the SNP header can be added to the unacknowledged packets list
    if not flow_control.send_packet(header):
        return None  # Cannot send packet due to flow control constraints


    header.data = encrypted_ip_packet

    global verifiable_data 
    verifiable_data = bytes(header)
    signature = digital_signature.sign_packet(bytes(header))
    
    return signature+ verifiable_data


def decapsulate(snp_packet, flow_control, digital_signature, encryption_key):
   

    header = SNPHeader(snp_packet)
   
    signature = snp_packet[:256]  # sugnature
    signed_data = snp_packet[256:] #verifiable data
 
    # Verify the digital signature
    if not digital_signature.verify_packet(signed_data, signature):
        print("Invalid Digital signature")
        alert_popup()
        

   # Retrieve the IV from the SNP header
    iv = header.iv

    header_length = len(header)
    encrypted_ip_packet = signed_data[21:53]

    ip_packet = decrypt(encrypted_ip_packet, iv, encryption_key)
    return ip_packet
    
    
if __name__ == "__main__":
    # Example usage with Flow Control:
    ip_packet = b"Hello, this is the IP packet!"
    source_id = 123
    dest_id = 456
    sequence_number = 1
    flags = 3

    # Create an instance of SNPFlowControl
    flow_control = SNPFlowControl()

    digital_signature = DigitalSignature(private_key, public_key)
    
    num_iterations = 1  # Set a number of iterations to prevent an infinite loop

    while num_iterations > 0:
        # Encapsulate the IP packet with the SNP header using Flow Control
        try:
            encapsulated_packet = encapsulate(ip_packet, source_id, dest_id, sequence_number, flags, flow_control,
                                              digital_signature)
        except ValueError as e:
            print("Error:", e)
            continue

        if encapsulated_packet is not None:
        
            # Decapsulate the packet and retrieve the original IP packet using Flow Control
            try:


                decapsulated_packet = decapsulate(encapsulated_packet, flow_control, digital_signature, encryption_key)
                #print("Decapsulated Packet:", decapsulated_packet)
            except ValueError as e:
                print("Error:", e)

        flow_control.check_timeouts()  # Check for packet timeouts and retransmit if necessary
        time.sleep(1)  # Sleep for a second before sending the next packet or checking timeouts

        num_iterations -= 1  # Decrement the number of iterations
