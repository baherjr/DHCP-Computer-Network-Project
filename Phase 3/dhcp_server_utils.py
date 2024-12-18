import socket
import struct
import binascii

# Server Configuration
SERVER_PORT = 67  # Port for the DHCP server
BROADCAST_ADDRESS = "255.255.255.0"  # Corrected broadcast address

# Error Codes
ERROR_CODES = {
    "MALFORMED_PACKET": "Malformed packet. Failed to parse the request.",
    "INVALID_TRANSACTION_ID": "Transaction ID is invalid or missing.",
    "INVALID_FLAGS": "Packet contains invalid flags.",
    "UNSUPPORTED_MESSAGE": "Unsupported DHCP message type.",
    "GENERAL_FAILURE": "A general processing failure occurred.",
}


def create_socket():
    """Create and configure the UDP socket."""
    server_socket = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    server_socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    server_socket.setsockopt(socket.SOL_SOCKET, socket.SO_BROADCAST, 1)

    # Bind to all interfaces on the desired port
    server_socket.bind(("0.0.0.0", SERVER_PORT))
    return server_socket


def parse_dhcp_packet(data):
    """Parse a raw DHCP packet and convert it into structured fields."""
    try:
        if len(data) < 240:
            print("Received packet is too small to be a valid DHCP packet.")
            return None

        # Unpack the fixed-length part of the DHCP packet
        packet = struct.unpack("!BBBB4sHHI4s4s4s4s16s64s128s", data[:240])
        dhcp_packet = {
            "op": packet[0],  # Message type: BOOTREQUEST (1) or BOOTREPLY (2)
            "htype": packet[1],  # Hardware type
            "hlen": packet[2],  # Hardware address length
            "hops": packet[3],  # Hops
            "xid": packet[4],  # Transaction ID
            "secs": packet[5],  # Seconds elapsed
            "flags": packet[6],  # Flags
            # Convert integers to bytes for inet_ntoa
            "ciaddr": socket.inet_ntoa(struct.pack('!I', packet[7])),
            "yiaddr": socket.inet_ntoa(struct.pack('!I', packet[8])),
            "siaddr": socket.inet_ntoa(struct.pack('!I', packet[9])),
            "giaddr": socket.inet_ntoa(struct.pack('!I', packet[10])),
            "chaddr": binascii.hexlify(packet[11][:packet[2]]).decode(),  # Client MAC Address
            "sname": packet[12].decode(errors="ignore").strip("\x00"),  # Server Host Name
            "file": packet[13].decode(errors="ignore").strip("\x00"),  # Boot Filename
            "magic_cookie": binascii.hexlify(data[236:240]).decode(),
        }
        # Parse DHCP options (remaining part of data)
        dhcp_packet["options"] = data[240:]
        return dhcp_packet
    except Exception as e:
        print(f"Error parsing packet: {e}")
        return None


def handle_dhcp_message(packet, server_socket, client_address):
    """Handle a DHCP message based on its type and current state."""
    try:
        # Parse the packet
        parsed_packet = parse_dhcp_packet(packet)

        if not parsed_packet:
            send_error_response(client_address, server_socket, "MALFORMED_PACKET")
            return

        # Identify the type of DHCP message
        dhcp_message_type = get_dhcp_message_type(parsed_packet["options"])

        if dhcp_message_type == 1:  # DHCPDISCOVER
            print(f"DHCPDISCOVER received from {client_address}")
            send_dhcp_offer(parsed_packet, server_socket, client_address)

        elif dhcp_message_type == 3:  # DHCPREQUEST
            print(f"DHCPREQUEST received from {client_address}")
            send_dhcp_ack(parsed_packet, server_socket, client_address)

        else:
            # If the message type is not supported, send an error
            print(f"Unsupported DHCP message type: {dhcp_message_type}")
            send_error_response(client_address, server_socket, "UNSUPPORTED_MESSAGE")

    except Exception as e:
        print(f"Error processing DHCP message: {e}")
        send_error_response(client_address, server_socket, "GENERAL_FAILURE")


def get_dhcp_message_type(options):
    """Extract the DHCP message type from the options field."""
    try:
        i = 0
        while i < len(options):
            option_type = options[i]
            option_length = options[i + 1]
            if option_type == 53:  # DHCP message type identifier
                return options[i + 2]
            i += 2 + option_length
        return None
    except Exception as e:
        print(f"Error extracting DHCP message type: {e}")
        return None


def send_dhcp_offer(parsed_packet, server_socket, client_address):
    """Send a DHCPOFFER response to the client."""
    response_packet = construct_dhcp_packet(
        transaction_id=parsed_packet["xid"],
        yiaddr="192.168.100.6",  # Example assigned IP address
        siaddr="192.168.100.1",  # DHCP server address
        dhcp_message_type=2,  # DHCPOFFER
    )
    # Send the response directly to the client's address instead of broadcasting
    server_socket.sendto(response_packet, client_address)
    print(f"DHCPOFFER sent to {client_address} with IP 192.168.1.100")


def send_dhcp_ack(parsed_packet, server_socket, client_address):
    """Send a DHCPACK response to the client."""
    response_packet = construct_dhcp_packet(
        transaction_id=parsed_packet["xid"],
        yiaddr="192.168.100.6",  # Example assigned IP address
        siaddr="192.168.100.1",  # DHCP server address
        dhcp_message_type=5,  # DHCPACK
    )
    # Send the response directly to the client's address
    server_socket.sendto(response_packet, client_address)
    print(f"DHCPACK sent to {client_address} confirming IP 192.168.1.100")


def construct_dhcp_packet(transaction_id, yiaddr, siaddr, dhcp_message_type):
    """Construct a simplified DHCP packet for response."""
    packet = struct.pack(
        "!BBBB4sHHHH4s4s4s4s16s64s128s",
        2,  # op: BOOTREPLY
        1,  # htype
        6,  # hlen
        0,  # hops
        transaction_id,  # xid
        0,  # secs
        0,  # flags
        0,  # ciaddr
        socket.inet_aton(yiaddr),  # yiaddr
        socket.inet_aton(siaddr),  # siaddr
        b"\x00\x00\x00\x00",  # giaddr
        b"\x00" * 16,  # chaddr
        b"\x00" * 64,  # sname
        b"\x00" * 128,  # file
    )
    # Add DHCP options (including message type)
    options = struct.pack("!BBB", 53, 1, dhcp_message_type) + b"\xff"
    return packet + options


def send_error_response(client_address, server_socket, error_code):
    """Send an error response with the corresponding error code."""
    error_message = ERROR_CODES.get(error_code, "Unknown error occurred.")
    server_socket.sendto(error_message.encode(), client_address)
    print(f"Error response sent to {client_address}: {error_message}")


def main():
    """Main entry point for the server."""
    server_socket = create_socket()
    print(f"DHCP server is running on port {SERVER_PORT}")

    while True:
        try:
            # Wait for inbound DHCP messages
            data, client_address = server_socket.recvfrom(1024)
            # In the main server loop
            if client_address == ('0.0.0.0', 68):
                print("Warning: Received packet from invalid address ('0.0.0.0', 68).")

            print(f"Received message from {client_address}")
            handle_dhcp_message(data, server_socket, client_address)

        except OSError as e:
            print(f"Socket error occurred: {e}")
        except Exception as e:
            print(f"An unexpected error occurred: {e}")


if __name__ == "__main__":
    main()
