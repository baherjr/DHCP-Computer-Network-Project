import socket
import struct
import binascii
from IPManager import IPManager

# Server Configuration
SERVER_PORT = 67  # Port for the DHCP server
CLIENT_PORT = 68  # Port for the DHCP client
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



def handle_dhcp_message(packet, server_socket, client_address, ip_manager):
    """Handle a DHCP message based on its type and current state."""
    try:
        # Parse the packet
        parsed_packet = parse_dhcp_packet(packet)

        if not parsed_packet:
            print("[WARNING] Failed to parse DHCP packet. Ignoring.")
            return

        # Identify the type of DHCP message
        dhcp_message_type = get_dhcp_message_type(parsed_packet["options"])

        if dhcp_message_type == 1:  # DHCPDISCOVER
            print(f"[INFO] DHCPDISCOVER received from {client_address}")
            send_dhcp_offer(parsed_packet, server_socket, client_address, ip_manager)

        elif dhcp_message_type == 3:  # DHCPREQUEST
            print(f"[INFO] DHCPREQUEST received from {client_address}")
            send_dhcp_ack(parsed_packet, server_socket, client_address, ip_manager)

        else:
            print(f"[WARNING] Unsupported DHCP message type: {dhcp_message_type}")

    except Exception as e:
        print(f"[ERROR] Error processing DHCP message: {e}")

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


def print_dhcp_packet(packet):
    """
    Print the contents of a DHCP packet in a readable format.
    
    Args:
        packet (bytes): The complete DHCP packet
    """
    print("\n=== DHCP Packet Contents ===")
    
    # Print fixed header fields (first 236 bytes)
    op = packet[0]
    htype = packet[1]
    hlen = packet[2]
    hops = packet[3]
    xid = packet[4:8].hex()
    secs = int.from_bytes(packet[8:10], 'big')
    flags = int.from_bytes(packet[10:12], 'big')
    ciaddr = '.'.join(str(b) for b in packet[12:16])
    yiaddr = '.'.join(str(b) for b in packet[16:20])
    siaddr = '.'.join(str(b) for b in packet[20:24])
    giaddr = '.'.join(str(b) for b in packet[24:28])
    chaddr = ':'.join(f'{b:02x}' for b in packet[28:34])  # First 6 bytes of chaddr (MAC address)
    
    print(f"""
    Op Code (op):          {op} ({'BOOTREQUEST' if op == 1 else 'BOOTREPLY'})
    Hardware Type (htype): {htype}
    Hardware Length:       {hlen}
    Hops:                 {hops}
    Transaction ID:       0x{xid}
    Seconds:             {secs}
    Flags:               0x{flags:04x}
    Client IP:           {ciaddr}
    Your IP:             {yiaddr}
    Server IP:           {siaddr}
    Gateway IP:          {giaddr}
    Client MAC:          {chaddr}
    """)
    
    # Print DHCP options
    print("=== DHCP Options ===")
    i = 240  # Start after fixed header and magic cookie
    while i < len(packet):
        if packet[i] == 255:  # End option
            print("End Option (255)")
            break
            
        option_type = packet[i]
        if i + 1 >= len(packet):
            break
            
        option_length = packet[i + 1]
        option_data = packet[i + 2:i + 2 + option_length]
        
        # Interpret common options
        option_str = f"Option {option_type}: "
        if option_type == 53:  # DHCP Message Type
            msg_types = {
                1: "DISCOVER",
                2: "OFFER",
                3: "REQUEST",
                4: "DECLINE",
                5: "ACK",
                6: "NAK",
                7: "RELEASE"
            }
            option_str += f"DHCP Message Type = {msg_types.get(option_data[0], option_data[0])}"
        elif option_type == 1:  # Subnet Mask
            mask = '.'.join(str(b) for b in option_data)
            option_str += f"Subnet Mask = {mask}"
        elif option_type == 3:  # Router
            router = '.'.join(str(b) for b in option_data)
            option_str += f"Router = {router}"
        elif option_type == 51:  # IP Address Lease Time
            lease_time = int.from_bytes(option_data, 'big')
            option_str += f"Lease Time = {lease_time} seconds"
        elif option_type == 54:  # DHCP Server Identifier
            server_id = '.'.join(str(b) for b in option_data)
            option_str += f"DHCP Server = {server_id}"
        else:
            option_str += f"Length = {option_length}, Data = {option_data.hex()}"
            
        print(option_str)
        i += 2 + option_length
    
    print("\n=== End of Packet ===\n")

def send_dhcp_offer(parsed_packet, server_socket, client_address, ip_manager):
    """Send a DHCPOFFER response to the client."""
    try:
        # Extract the client MAC address from the parsed packet
        client_mac = parsed_packet["chaddr"]
        print(f"[INFO] Processing DHCPDISCOVER for MAC: {client_mac}")

        # Get the next available IP address from IPManager
        offered_ip = ip_manager.get_next_available_ip(client_mac)

        if not offered_ip:
            print(f"[WARNING] No IP available for MAC {client_mac}. Cannot send DHCPOFFER.")
            return

        # Create the DHCPOFFER packet using the assigned IP and client's MAC
        response_packet = construct_dhcp_packet(
            transaction_id=parsed_packet["xid"],
            yiaddr=offered_ip,
            ip_manager=ip_manager,
            dhcp_message_type=2,  # DHCPOFFER
            client_mac=client_mac  # MAC string will be converted to bytes in construct_dhcp_packet
        )

        print_dhcp_packet(response_packet)

        # Send the response directly to the client's address
        server_socket.sendto(response_packet, (BROADCAST_ADDRESS,CLIENT_PORT))

        # Log success and record the lease with configured lease time
        lease_time = ip_manager.config['lease_settings']['default_lease_time']
        print(f"[INFO] DHCPOFFER sent to {client_address} with IP {offered_ip}")
        ip_manager.add_lease(offered_ip, client_mac, lease_time)
    except Exception as e:
        print(f"[ERROR] Failed to send DHCPOFFER: {e}")


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


def mac_str_to_bytes(mac_str):
    """Convert a MAC address string to bytes.
    
    Args:
        mac_str (str): MAC address in format "XX:XX:XX:XX:XX:XX"
    
    Returns:
        bytes: MAC address as bytes
    """
    # Remove any separators and convert to bytes
    mac_clean = mac_str.replace(':', '').replace('-', '')
    return bytes.fromhex(mac_clean)

def construct_dhcp_packet(transaction_id, yiaddr, ip_manager, dhcp_message_type, client_mac):
    """
    Simplified DHCP packet construction using configuration from IPManager.
    
    Args:
        transaction_id (bytes): The transaction ID from the client request
        yiaddr (str): The offered IP address
        ip_manager (IPManager): Instance of IPManager containing configuration
        dhcp_message_type (int): DHCP message type (1=DISCOVER, 2=OFFER, 3=REQUEST, 4=DECLINE, etc.)
        client_mac (str): Client's MAC address from the DISCOVER request
    
    Returns:
        bytes: The complete DHCP packet
    """
    # Get network configuration from ip_manager
    config = ip_manager.config
    server_ip = config['server']['server_ip']
    subnet_mask = config['network']['subnet_mask']
    router = config['network']['router']
    dns_servers = config['network']['dns_servers']
    lease_time = config['lease_settings']['default_lease_time']
    renewal_time = config['lease_settings']['renewal_time']
    rebinding_time = config['lease_settings']['rebinding_time']

    # Debug print to check transaction_id type
    print(f"[DEBUG] transaction_id type: {type(transaction_id)}, value: {transaction_id}")
    
    # Ensure transaction_id is bytes
    if isinstance(transaction_id, int):
        transaction_id = transaction_id.to_bytes(4, byteorder='big')
    elif isinstance(transaction_id, str):
        transaction_id = bytes.fromhex(transaction_id.replace('0x', ''))
    
    # Convert string IPs to network byte order
    yiaddr = socket.inet_aton(yiaddr)
    siaddr = socket.inet_aton(server_ip)
    
    # Convert MAC address string to bytes
    client_mac_bytes = mac_str_to_bytes(client_mac)
    
    # Default values for standard DHCP OFFER
    op = 2  # Boot Reply
    htype = 1  # Ethernet
    hlen = 6  # Hardware address length for Ethernet
    hops = 0
    secs = 0
    flags = 0
    ciaddr = bytes([0] * 4)  # Client IP address (empty for OFFER)
    giaddr = bytes([0] * 4)  # Relay agent IP address
    
    # Prepare DHCP options
    options = [
        {'type': 53, 'length': 1, 'value': bytes([dhcp_message_type])},  # DHCP Message Type
        {'type': 1, 'length': 4, 'value': socket.inet_aton(subnet_mask)},  # Subnet Mask
        {'type': 3, 'length': 4, 'value': socket.inet_aton(router)},  # Router
        {'type': 51, 'length': 4, 'value': struct.pack('!L', lease_time)},  # IP Address Lease Time
        {'type': 58, 'length': 4, 'value': struct.pack('!L', renewal_time)},  # Renewal Time Value
        {'type': 59, 'length': 4, 'value': struct.pack('!L', rebinding_time)},  # Rebinding Time Value
        {'type': 54, 'length': 4, 'value': socket.inet_aton(server_ip)},  # DHCP Server Identifier
    ]
    
    # Add DNS servers option
    dns_bytes = b''.join(socket.inet_aton(dns) for dns in dns_servers)
    options.append({
        'type': 6,
        'length': len(dns_bytes),
        'value': dns_bytes
    })
    
    # Add End Option
    options.append({'type': 255, 'length': 0, 'value': b''})
    print("simple offer created")
    return construct_dhcp_packet_full(
        op=op,
        htype=htype,
        hlen=hlen,
        hops=hops,
        xid=transaction_id,
        secs=secs,
        flags=flags,
        ciaddr=ciaddr,
        yiaddr=yiaddr,
        siaddr=siaddr,
        giaddr=giaddr,
        chaddr=client_mac_bytes,
        options=options
    )


def construct_dhcp_packet_full(op, htype, hlen, hops, xid, secs, flags,
                             ciaddr, yiaddr, siaddr, giaddr, chaddr, options):
    """
    Construct a complete DHCP packet with all fields specified.
    """
    try:
        # Debug print of all packed values
        print(f"[DEBUG] Packing values:")
        print(f"op: {type(op)}, value: {op}")
        print(f"htype: {type(htype)}, value: {htype}")
        print(f"hlen: {type(hlen)}, value: {hlen}")
        print(f"hops: {type(hops)}, value: {hops}")
        print(f"xid: {type(xid)}, value: {xid}")
        print(f"secs: {type(secs)}, value: {secs}")
        print(f"flags: {type(flags)}, value: {flags}")
        
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
        
    except Exception as e:
        print(f"[DEBUG] Pack error details: {str(e)}")
        raise


def send_error_response(client_address, server_socket, error_code):
    """Send an error response with the corresponding error code."""
    error_message = ERROR_CODES.get(error_code, "Unknown error occurred.")
    server_socket.sendto(error_message.encode(), client_address)
    print(f"Error response sent to {client_address}: {error_message}")


def main():
    """Main entry point for the server."""
    # Initialize the IPManager with a sample config file path
    ip_manager = IPManager(config_path="F:/ASU/YEAR 4/Semester 1/CSE351 - Networks/Project/Networks/Phase 3/configs.json")

    # Create and set up the server socket
    server_socket = create_socket()
    print(f"[INFO] DHCP server is running on port {SERVER_PORT}")

    while True:
        try:
            # Wait for inbound DHCP messages
            data, client_address = server_socket.recvfrom(1024)

            # Log the received message
            print(f"[INFO] Received message from {client_address}")

            # Process the DHCP message
            handle_dhcp_message(data, server_socket, client_address, ip_manager)

        except OSError as e:
            print(f"[ERROR] Socket error occurred: {e}")
        except Exception as e:
            print(f"[ERROR] An unexpected error occurred: {e}")

if __name__ == "__main__":
    main()
