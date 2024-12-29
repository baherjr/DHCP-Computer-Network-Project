import socket
import struct
import binascii
import IPManager

# Server Configuration
SERVER_PORT = 67  # Port for the DHCP server
BROADCAST_ADDRESS = "255.255.255.255"  # Corrected broadcast address

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
    """Parse a raw DHCP packet and convert it into structured fields with detailed logging."""
    try:
        if len(data) < 240:
            print("Received packet is too small to be a valid DHCP packet.")
            return None

        print("[DEBUG] Unpacking fixed-length DHCP fields...")

        # Unpack the fixed-length part of the DHCP packet
        packet = struct.unpack("!BBBB4sHHI4s4s4s4s16s64s128s", data[:240])

        # Debugging each field unpacked
        print(f"[DEBUG] Message Type (op): {packet[0]}")
        print(f"[DEBUG] Hardware Type (htype): {packet[1]}")
        print(f"[DEBUG] Hardware Address Length (hlen): {packet[2]}")
        print(f"[DEBUG] Hops: {packet[3]}")
        print(f"[DEBUG] Transaction ID (xid): {binascii.hexlify(packet[4]).decode()}")
        print(f"[DEBUG] Seconds elapsed (secs): {packet[5]}")
        print(f"[DEBUG] Flags: {packet[6]}")

        # For IP addresses, they are already in packed format from struct.unpack
        try:
            # Store the packed IP addresses directly
            ciaddr = packet[8]  # Client IP Address
            yiaddr = packet[9]  # Your IP Address
            siaddr = packet[10]  # Server IP Address
            giaddr = packet[11]  # Gateway IP Address
            
            # Print human-readable format for debugging
            print(f"[DEBUG] Client IP Address (ciaddr): {socket.inet_ntoa(ciaddr)}")
            print(f"[DEBUG] Your IP Address (yiaddr): {socket.inet_ntoa(yiaddr)}")
            print(f"[DEBUG] Server IP Address (siaddr): {socket.inet_ntoa(siaddr)}")
            print(f"[DEBUG] Gateway IP Address (giaddr): {socket.inet_ntoa(giaddr)}")
        except Exception as e:
            print(f"[ERROR] Issue with IP addresses: {e}")
            raise

        # For MAC address, ensure proper slicing of bytes
        try:
            chaddr = binascii.hexlify(packet[11][:packet[2]]).decode()
        except Exception as e:
            print(f"[ERROR] Issue decoding Client Hardware Address (chaddr): {e}")
            raise

        print(f"[DEBUG] Client MAC Address (chaddr): {chaddr}")

        # Ensure sname and file are decoded properly
        try:
            sname = packet[12].decode(errors="ignore").strip("\x00")
            file = packet[13].decode(errors="ignore").strip("\x00")
        except Exception as e:
            print(f"[ERROR] Issue decoding sname/file: {e}")
            raise

        print(f"[DEBUG] Server Host Name (sname): {sname}")
        print(f"[DEBUG] Boot Filename (file): {file}")

        # Ensure magic cookie is valid
        try:
            magic_cookie = binascii.hexlify(data[236:240]).decode()
        except Exception as e:
            print(f"[ERROR] Issue decoding magic cookie: {e}")
            raise

        print(f"[DEBUG] Magic cookie: {magic_cookie}")

        dhcp_packet = {
            "op": packet[0],
            "htype": packet[1],
            "hlen": packet[2],
            "hops": packet[3],
            "xid": binascii.hexlify(packet[4]).decode(),
            "secs": packet[5],
            "flags": packet[6],
            "ciaddr": ciaddr,  # Packed IP address
            "yiaddr": yiaddr,  # Packed IP address
            "siaddr": siaddr,  # Packed IP address
            "giaddr": giaddr,  # Packed IP address
            "chaddr": chaddr,
            "sname": sname,
            "file": file,
            "magic_cookie": magic_cookie,
        }

        # Parse DHCP options
        print("[DEBUG] Parsing DHCP options...")
        options = parse_dhcp_options(data[240:])
        dhcp_packet["options"] = options

        return dhcp_packet
    except Exception as e:
        print(f"Error parsing packet: {e}")
        raise


def parse_dhcp_options(options_data):
    """Parse DHCP options from the raw data with debugging."""
    options = []
    i = 0
    try:
        while i < len(options_data):
            option_type = options_data[i]

            print(f"[DEBUG] Option Type: {option_type}")

            # End option (255)
            if option_type == 255:
                options.append({"type": 255, "length": 0, "value": None})
                print("[DEBUG] End Option (255) reached.")
                break

            # Padding option (0)
            elif option_type == 0:
                print("[DEBUG] Padding Option (0) found.")
                i += 1
                continue

            # Other options
            else:
                i += 1
                if i >= len(options_data):
                    print("[ERROR] Malformed DHCP options: missing length field.")
                    break

                length = options_data[i]
                i += 1
                if i + length > len(options_data):
                    print(f"[ERROR] Malformed DHCP option: Option {option_type} exceeds data bounds.")
                    break

                value = options_data[i:i + length]
                options.append({"type": option_type, "length": length, "value": value})
                print(f"[DEBUG] Parsed Option: {option_type}, Length: {length}, Value: {value}")
                i += length

    except Exception as e:
        print(f"[ERROR] Exception while parsing options: {e}")
        raise

    return options



def handle_dhcp_message(packet, server_socket, client_address):
    """Handle a DHCP message based on its type and current state."""
    try:
        # Parse the packet
        parsed_packet = parse_dhcp_packet(packet)
        print("entered handling")
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
    """Extract the DHCP message type from the structured options field."""
    try:
        for option in options:
            if option["type"] == 53:  # DHCP message type identifier
                return option["value"][0]  # First byte of value
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


def construct_dhcp_packet(op, htype, hlen, hops, xid, secs, flags,
                         ciaddr, yiaddr, siaddr, giaddr, chaddr, options):
    """
    Construct a DHCP packet with the specified fields.
    
    Returns:
        bytes: The complete DHCP packet
    """
    # Pad chaddr to 16 bytes
    chaddr = chaddr + bytes([0] * (16 - len(chaddr)))
    
    # Empty server hostname and boot filename
    sname = bytes([0] * 64)
    file = bytes([0] * 128)
    
    # Magic cookie for DHCP
    magic_cookie = bytes([99, 130, 83, 99])
    
    # Construct the fixed part of the packet
    packet = struct.pack('!BBBB4sHH4s4s4s4s16s64s128s4s',
        op, htype, hlen, hops,
        xid, secs, flags,
        ciaddr, yiaddr, siaddr, giaddr,
        chaddr, sname, file, magic_cookie
    )
    
    # Add options
    for option in options:
        if option['type'] == 255:  # End option
            packet += bytes([option['type']])
        else:
            packet += bytes([option['type'], option['length']]) + option['value']
    
    return packet


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
            if client_address != ('0.0.0.0', 68):
                print("Warning: Received packet from invalid address ('0.0.0.0', 68).")

            print(f"Received message from {client_address}")
            handle_dhcp_message(data, server_socket, client_address)

        except OSError as e:
            print(f"Socket error occurred: {e}")
        except Exception as e:
            print(f"An unexpected error occurred: {e}")


if __name__ == "__main__":
    main()
