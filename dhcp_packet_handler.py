import socket
from dhcp_packet import DHCPPacket

# Create a socket to listen for incoming DHCP packets (UDP on port 67)
sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
sock.bind(('0.0.0.0', 67))  # Bind to all interfaces on port 67

while True:
    try:
        # Receive DHCP Packet
        data, addr = sock.recvfrom(1024)
        print(f"Received packet from {addr}")

        # Decode the packet
        packet = DHCPPacket()
        packet.decodePacket(data.hex())
        print(f"Decoded packet: {packet.decoded}")

        # Check if it's a DHCP Discover (type 1)
        if packet.type == 1:
            print("DHCP Discover received!")
            # Respond with DHCP Offer...
        else:
            print(f"Unexpected packet type: {packet.type}")
    except Exception as e:
        print(f"Error handling packet: {e}")