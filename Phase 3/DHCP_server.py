import socket
import struct
import binascii
import threading
import time
from IPManager import IPManager


# Error Codes
ERROR_CODES = {
    "MALFORMED_PACKET": "Malformed packet. Failed to parse the request.",
    "INVALID_TRANSACTION_ID": "Transaction ID is invalid or missing.",
    "INVALID_FLAGS": "Packet contains invalid flags.",
    "UNSUPPORTED_MESSAGE": "Unsupported DHCP message type.",
    "GENERAL_FAILURE": "A general processing failure occurred.",
}

# ************************************************ Socket Utilities ************************************************
def create_socket(SERVER_PORT):
    """Create and configure the UDP socket."""
    server_socket = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    server_socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    server_socket.setsockopt(socket.SOL_SOCKET, socket.SO_BROADCAST, 1)
    # server_socket.setblocking(False)
    #server_socket.settimeout(5.0)  # 5 seconds timeout

    # Bind to all interfaces on the desired port
    server_socket.bind(("0.0.0.0", SERVER_PORT))
    return server_socket

def send_error_response(client_address, server_socket, error_code):
    """Send an error response with the corresponding error code."""
    error_message = ERROR_CODES.get(error_code, "Unknown error occurred.")
    server_socket.sendto(error_message.encode(), client_address)
    print(f"Error response sent to {client_address}: {error_message}")

# ************************************************ Packet Parsing and Construction ************************************************
def parse_dhcp_packet(data):
    """Parse a raw DHCP packet and convert it into structured fields with detailed logging."""
    try:
        print(f"Raw DHCP message (hex): {binascii.hexlify(data).decode()}")
        if len(data) < 240:
            print("Received packet is too small to be a valid DHCP packet.")
            return None

        print("[DEBUG] Parsing fixed-length DHCP fields...")

        # Parse fixed-length fields manually
        op = data[0]
        htype = data[1]
        hlen = data[2]
        hops = data[3]
        xid = data[4:8]
        secs = int.from_bytes(data[8:10], 'big')
        flags = int.from_bytes(data[10:12], 'big')
        ciaddr = data[12:16]  # Keep as bytes for consistency
        yiaddr = data[16:20]
        siaddr = data[20:24]
        giaddr = data[24:28]
        chaddr = data[28:28 + hlen].hex()  # Convert MAC to hex string
        sname = data[44:108].decode('ascii').rstrip('\x00')  # Remove null bytes
        file = data[108:236].decode('ascii').rstrip('\x00')
        magic_cookie = data[236:240].hex()

        # Debug logging
        print(f"[DEBUG] Message Type (op): {op}")
        print(f"[DEBUG] Hardware Type (htype): {htype}")
        print(f"[DEBUG] Hardware Address Length (hlen): {hlen}")
        print(f"[DEBUG] Hops: {hops}")
        print(f"[DEBUG] Transaction ID (xid): {binascii.hexlify(xid).decode()}")
        print(f"[DEBUG] Seconds elapsed (secs): {secs}")
        print(f"[DEBUG] Flags: {flags}")

        # Print IP addresses for debugging
        try:
            print(f"[DEBUG] Client IP Address (ciaddr): {socket.inet_ntoa(ciaddr)}")
            print(f"[DEBUG] Your IP Address (yiaddr): {socket.inet_ntoa(yiaddr)}")
            print(f"[DEBUG] Server IP Address (siaddr): {socket.inet_ntoa(siaddr)}")
            print(f"[DEBUG] Gateway IP Address (giaddr): {socket.inet_ntoa(giaddr)}")
        except Exception as e:
            print(f"[ERROR] Issue with IP addresses: {e}")
            raise

        print(f"[DEBUG] Client MAC Address (chaddr): {chaddr}")
        print(f"[DEBUG] Server Host Name (sname): {sname}")
        print(f"[DEBUG] Boot Filename (file): {file}")
        print(f"[DEBUG] Magic cookie: {magic_cookie}")

        # Create the packet dictionary with the same structure as before
        dhcp_packet = {
            "op": op,
            "htype": htype,
            "hlen": hlen,
            "hops": hops,
            "xid": binascii.hexlify(xid).decode(),
            "secs": secs,
            "flags": flags,
            "ciaddr": ciaddr,  # Keeping as packed bytes
            "yiaddr": yiaddr,  # Keeping as packed bytes
            "siaddr": siaddr,  # Keeping as packed bytes
            "giaddr": giaddr,  # Keeping as packed bytes
            "chaddr": chaddr,
            "sname": sname,
            "file": file,
            "magic_cookie": magic_cookie,
        }

        # Parse DHCP options manually
        print("[DEBUG] Parsing DHCP options...")
        options = []
        i = 240  # Start of options

        while i < len(data):
            option_type = data[i]

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

            # Regular options
            else:
                if i + 1 >= len(data):
                    print("[ERROR] Malformed DHCP options: missing length field.")
                    break

                length = data[i + 1]
                if i + 2 + length > len(data):
                    print(f"[ERROR] Malformed DHCP option: Option {option_type} exceeds data bounds.")
                    break

                value = data[i + 2:i + 2 + length]
                
                # Decode the option based on its type
                option_str = f"[DEBUG] Parsed Option: {option_type}, Length: {length}, Value: "
                if option_type == 50:  # Requested IP Address
                    option_str += f"Requested IP Address = {socket.inet_ntoa(value)}"
                elif option_type == 60:  # Vendor Class Identifier
                    option_str += f"Vendor Class Identifier = {value.decode('ascii')}"
                elif option_type == 12:  # Host Name
                    option_str += f"Host Name = {value.decode('ascii')}"
                elif option_type == 53:  # DHCP Message Type
                    msg_types = {
                        1: "DHCPDISCOVER",
                        2: "DHCPOFFER",
                        3: "DHCPREQUEST",
                        4: "DHCPDECLINE",
                        5: "DHCPACK",
                        6: "DHCPNAK",
                        7: "DHCPRELEASE",
                        8: "DHCPINFORM"
                    }
                    option_str += f"DHCP Message Type = {msg_types.get(value[0], 'Unknown')}"
                elif option_type == 1:  # Subnet Mask
                    option_str += f"Subnet Mask = {socket.inet_ntoa(value)}"
                elif option_type == 3:  # Router
                    option_str += f"Router = {socket.inet_ntoa(value)}"
                elif option_type == 6:  # DNS Servers
                    dns_servers = [socket.inet_ntoa(value[i:i+4]) for i in range(0, len(value), 4)]
                    option_str += f"DNS Servers = {', '.join(dns_servers)}"
                elif option_type == 51:  # Lease Time
                    lease_time = int.from_bytes(value, 'big')
                    option_str += f"Lease Time = {lease_time} seconds"
                elif option_type == 54:  # DHCP Server Identifier
                    option_str += f"DHCP Server = {socket.inet_ntoa(value)}"
                elif option_type == 58:  # Renewal Time
                    renewal_time = int.from_bytes(value, 'big')
                    option_str += f"Renewal Time = {renewal_time} seconds"
                elif option_type == 59:  # Rebinding Time
                    rebinding_time = int.from_bytes(value, 'big')
                    option_str += f"Rebinding Time = {rebinding_time} seconds"
                else:
                    option_str += f"Raw Data = {binascii.hexlify(value).decode()}"

                print(option_str)
                options.append({"type": option_type, "length": length, "value": value})
                i += 2 + length

        dhcp_packet["options"] = options
        return dhcp_packet

    except Exception as e:
        print(f"Error parsing packet: {e}")
        raise

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
    server_ip = ip_manager.get_server_ip()
    subnet_mask = ip_manager.get_subnet_mask()
    router = ip_manager.get_router()
    dns_servers = ip_manager.get_dns_servers()
    lease_time = ip_manager.get_lease_time()
    renewal_time = ip_manager.get_renewal_time()
    rebinding_time = ip_manager.get_rebinding_time()

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
        print(f"transaction ID: 0x{xid.hex()}")
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

# ************************************************ DHCP Message Handling ************************************************
def handle_dhcp_message(packet, server_socket, client_address, ip_manager, BROADCAST_ADDRESS, CLIENT_PORT):
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
            send_dhcp_offer(parsed_packet, server_socket, client_address, ip_manager, BROADCAST_ADDRESS, CLIENT_PORT)

        elif dhcp_message_type == 3:  # DHCPREQUEST
            print(f"[INFO] DHCPREQUEST received from {client_address}")
            handle_dhcp_request(parsed_packet, server_socket, client_address, ip_manager, BROADCAST_ADDRESS, CLIENT_PORT)

        elif dhcp_message_type == 7:  # DHCPRELEASE
            print(f"[INFO] DHCPRELEASE received from {client_address}")
            handle_dhcp_release(parsed_packet, ip_manager)

        elif dhcp_message_type == 8:  # DHCPINFORM
            print(f"[INFO] DHCPINFORM received from {client_address}")
            handle_dhcp_inform(parsed_packet, server_socket, client_address, ip_manager, BROADCAST_ADDRESS, CLIENT_PORT)

        elif dhcp_message_type == 4:  # DHCPDECLINE
            print(f"[INFO] DHCPDECLINE received from {client_address}")
            handle_dhcp_decline(parsed_packet, ip_manager)

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

def send_dhcp_offer(parsed_packet, server_socket, client_address, ip_manager, BROADCAST_ADDRESS, CLIENT_PORT):
    """Send a DHCPOFFER response to the client."""
    try:
        # Extract the client MAC address from the parsed packet
        client_mac = parsed_packet["chaddr"]
        print(f"[INFO] Processing DHCPDISCOVER for MAC: {client_mac}")

        # Get the next available IP address from IPManager
        offered_ip = ip_manager.get_next_available_ip(client_mac)
        ip_manager.set_current_ip(offered_ip)

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
        print(f"[INFO] DHCPOFFER sent to {client_address} with IP {ip_manager.get_current_ip()}")

    except Exception as e:
        print(f"[ERROR] Failed to send DHCPOFFER: {e}")

def send_dhcp_ack(parsed_packet, server_socket, client_address, ip_manager, BROADCAST_ADDRESS, CLIENT_PORT):
    """Send a DHCPACK response to the client."""
    client_mac = parsed_packet["chaddr"]
    print(f"[INFO] Processing DHCPREQUEST for MAC: {client_mac}")

    response_packet = construct_dhcp_packet(
        transaction_id=parsed_packet["xid"],
        yiaddr=ip_manager.get_current_ip(),  # Offered IP address
        ip_manager=ip_manager,
        dhcp_message_type=5,  # DHCPACK
        client_mac=client_mac  # MAC string will be converted to bytes in construct_dhcp_packet
    )
   
    print_dhcp_packet(response_packet)

    # Send the response directly to the client's address
    server_socket.sendto(response_packet, (BROADCAST_ADDRESS,CLIENT_PORT))
    # Log success and record the lease with configured lease time
    lease_time = ip_manager.config['lease_settings']['default_lease_time']
    ip_manager.add_lease(ip_manager.get_current_ip(), client_mac, lease_time)
    print(f"DHCPACK sent to {client_address} confirming IP {ip_manager.get_current_ip()}")

def send_dhcp_nak(parsed_packet, server_socket, client_address, ip_manager, BROADCAST_ADDRESS, CLIENT_PORT):
    """Send a DHCPNAK response to the client."""
    try:
        client_mac = parsed_packet["chaddr"]

        # Construct the DHCPNAK packet
        response_packet = construct_dhcp_packet(
            transaction_id=parsed_packet["xid"],
            yiaddr="0.0.0.0",  # NAK does not assign an IP
            ip_manager=ip_manager,
            dhcp_message_type=6,  # DHCPNAK
            client_mac=client_mac
        )

        # Send the response directly to the client's address
        server_socket.sendto(response_packet, (BROADCAST_ADDRESS, CLIENT_PORT))
        print(f"[INFO] DHCPNAK sent to {client_address} for MAC {client_mac}")

    except Exception as e:
        print(f"[ERROR] Failed to send DHCPNAK: {e}")

def handle_dhcp_request(parsed_packet, server_socket, client_address, ip_manager, BROADCAST_ADDRESS, CLIENT_PORT):
    """Handle a DHCPREQUEST message by sending either DHCPACK or DHCPNAK."""
    try:
        def normalize_mac(mac):
            # Remove any separators and convert to lowercase
            mac_clean = mac.replace(':', '').replace('-', '').lower()
            # Reformat to colon-separated format
            return ':'.join(mac_clean[i:i+2] for i in range(0, 12, 2))
        
        def check_mac_equivalence(mac1,mac2):
            normalize_mac(mac1)
            normalize_mac(mac2)
            return mac1 == mac2
        
        client_mac = parsed_packet["chaddr"]
        # Define the MAC address to check against
        TARGET_MAC = "88:52:eb:9f:71:92" # Redmi note 11's MAC address
        requested_ip = "10.0.1.14" # Outsider IP since our subnet range is 192.168.1.0/24 

        # Check if the client's MAC address matches the target value
        if not check_mac_equivalence(client_mac,TARGET_MAC):
            requested_ip = None 

            # Extract the requested IP from the DHCP options (if present)
            for option in parsed_packet["options"]:
                if option["type"] == 50:  # Requested IP Address option
                    requested_ip = socket.inet_ntoa(option["value"])
                    break

        # If no requested IP is found, use the ciaddr field
        if not requested_ip:
            requested_ip = socket.inet_ntoa(parsed_packet["ciaddr"])

        print(f"[INFO] DHCPREQUEST received from {client_address} for IP {requested_ip}")

        # Check if the requested IP is available
        if ip_manager.is_ip_available(requested_ip) and not ip_manager.is_mac_blocked(client_mac):
            # If the IP is available, send DHCPACK
            print(f"[INFO] IP {requested_ip} is available. Sending DHCPACK.")
            send_dhcp_ack(parsed_packet, server_socket, client_address, ip_manager, BROADCAST_ADDRESS, CLIENT_PORT)
        else:
            # If the IP is not available, send DHCPNAK
            print(f"[INFO] IP {requested_ip} is not available. Sending DHCPNAK.")
            send_dhcp_nak(parsed_packet, server_socket, client_address, ip_manager, BROADCAST_ADDRESS, CLIENT_PORT)

    except Exception as e:
        print(f"[ERROR] Failed to handle DHCPREQUEST: {e}")

def handle_dhcp_release(parsed_packet, ip_manager):
    """Handle a DHCPRELEASE message by releasing the IP address."""
    try:
        client_mac = parsed_packet["chaddr"]
        client_ip = socket.inet_ntoa(parsed_packet["ciaddr"])

        # Remove the lease from the active leases
        ip_manager.remove_lease(client_ip)
        print(f"[INFO] Released IP {client_ip} for MAC {client_mac}")

    except Exception as e:
        print(f"[ERROR] Failed to handle DHCPRELEASE: {e}")

def handle_dhcp_inform(parsed_packet, server_socket, client_address, ip_manager, BROADCAST_ADDRESS, CLIENT_PORT):
    """Handle a DHCPINFORM message by sending a DHCPACK with configuration."""
    try:
        client_mac = parsed_packet["chaddr"]
        client_ip = socket.inet_ntoa(parsed_packet["ciaddr"])

        # Create a DHCPACK packet with the current configuration
        response_packet = construct_dhcp_packet(
            transaction_id=parsed_packet["xid"],
            yiaddr=client_ip,
            ip_manager=ip_manager,
            dhcp_message_type=5,  # DHCPACK
            client_mac=client_mac
        )

        # Send the response directly to the client's address
        server_socket.sendto(response_packet, (BROADCAST_ADDRESS, CLIENT_PORT))
        print(f"[INFO] DHCPACK sent to {client_address} with configuration for IP {client_ip}")

    except Exception as e:
        print(f"[ERROR] Failed to handle DHCPINFORM: {e}")

def handle_dhcp_decline(parsed_packet, ip_manager):
    """Handle a DHCPDECLINE message by marking the IP as unavailable."""
    try:
        client_mac = parsed_packet["chaddr"]
        declined_ip = socket.inet_ntoa(parsed_packet["ciaddr"])

        # Remove the lease and mark the IP as unavailable
        ip_manager.remove_lease(declined_ip)
        print(f"[INFO] Declined IP {declined_ip} for MAC {client_mac}")

    except Exception as e:
        print(f"[ERROR] Failed to handle DHCPDECLINE: {e}")

# ************************************************ Packet Printing ************************************************
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
    chaddr = ':'.join(f'{b:02x}' for b in packet[28:44])  # First 6 bytes of chaddr (MAC address)
    
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

# ************************************************ Clean-up Function ************************************************

    # Start a background thread to periodically clean up expired leases
def lease_cleanup_task(ip_manager):
    """Background task to periodically clean up expired leases."""
    while True:
        try:
            ip_manager.cleanup_expired_leases()
            time.sleep(5)  # Run cleanup every hour (3600 seconds)
        except Exception as e:
            print(f"[ERROR] Lease cleanup task failed: {e}")
            time.sleep(60)  # Wait a minute before retrying if an error occurs

# ************************************************ Main Function ************************************************
def main():
    """Main entry point for the server."""
    # Initialize the IPManager with a sample config file path
    ip_manager = IPManager(config_path="F:/ASU/YEAR 4/Semester 1/CSE351 - Networks/Project/Networks/Phase 3/configs.json")

    # Server Configuration
    SERVER_PORT = ip_manager.get_listening_port()  # Port for the DHCP server
    CLIENT_PORT = ip_manager.get_client_port()  # Port for the DHCP client
    BROADCAST_ADDRESS = ip_manager.get_broadcast_address()  # Corrected broadcast address

    # Create and set up the server socket
    server_socket = create_socket(SERVER_PORT)
    print(f"[INFO] DHCP server is running on port {SERVER_PORT}")

     # Start the lease cleanup thread
    cleanup_thread = threading.Thread(target=lease_cleanup_task, args=(ip_manager,), daemon=True)
    cleanup_thread.start()
    print("[INFO] Lease cleanup task started.")
    
    while True:
        try:
            # Wait for inbound DHCP messages
            data, client_address = server_socket.recvfrom(1024)

            # Log the received message
            print(f"[INFO] Received message from {client_address}")

            # Process the DHCP message
            handle_dhcp_message(data, server_socket, client_address, ip_manager, BROADCAST_ADDRESS, CLIENT_PORT)
        except OSError as e:
            print(f"[ERROR] Socket error occurred: {e}")
        except Exception as e:
            print(f"[ERROR] An unexpected error occurred: {e}")

if __name__ == "__main__":
    main()
