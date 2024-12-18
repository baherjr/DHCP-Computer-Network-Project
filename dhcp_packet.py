

class DHCPPacket:
    def __init__(self):
        # DHCP packet structure
        self.type = 0  # DHCP message type
        self.xid = []  # Transaction ID
        self.macAddress = ""  # Client MAC address
        self.yiaddr = ""  # Client IP address (offered)
        self.siaddr = ""  # Server IP address
        self.hostname = ""  # Client hostname
        self.lease_time = 0  # Lease time in seconds
        self.sendMessage = ""  # Full packet in hex for sending
        self.decoded = ""  # Human-readable decoded packet

    def setMessage(
            self,
            type,
            transactionID,
            client_mac_address,
            elapsed_time=0,
            client_ip_address="0.0.0.0",
            server_ip_address="0.0.0.0",
            host_name="",
            lease_time=0,
    ):
        """
        Constructs the DHCP packet as a hex string based on provided fields.
        """
        try:
            # DHCP header fields
            OP = "02" if type in ["02", "05"] else "01"  # Response (2) or Request (1)
            HTYPE = "01"  # Ethernet
            HLEN = "06"  # MAC length
            HOPS = "00"  # No relay
            XID = "".join(transactionID)  # Transaction ID
            SECS = f"{elapsed_time:04x}" if elapsed_time else "00" * 2  # Elapsed time
            FLAGS = "00" * 2  # No special flags
            CIADDR = "00" * 4  # Client address placeholder
            YIADDR = "".join([f"{int(octet):02x}" for octet in client_ip_address.split(".")])
            SIADDR = "".join([f"{int(octet):02x}" for octet in server_ip_address.split(".")])
            GIADDR = "00" * 4  # Gateway IP
            CHADDR = "".join([f"{int(octet, 16):02x}" for octet in client_mac_address.split(":")])
            CHADDR += "00" * 10  # Padding to 16 bytes
            SNAME = "00" * 64  # Next server placeholder
            FILE = "00" * 128  # Boot filename placeholder

            # DHCP options
            MAGICCOOKIE = "63825363"  # DHCP magic cookie

            # Mandatory options
            OPTION1 = f"35{len(type):02x}{type}"  # Message type option
            OPTION2 = ""

            if lease_time > 0:
                OPTION2 += "3304" + f"{lease_time:08x}"

            if host_name:
                OPTION2 += f"0c{len(host_name):02x}" + "".join(f"{ord(c):02x}" for c in host_name)

            END = "ff"  # End of options

            # Finalize packet
            packet = (
                    OP
                    + HTYPE
                    + HLEN
                    + HOPS
                    + XID
                    + SECS
                    + FLAGS
                    + CIADDR
                    + YIADDR
                    + SIADDR
                    + GIADDR
                    + CHADDR
                    + SNAME
                    + FILE
                    + MAGICCOOKIE
                    + OPTION1
                    + OPTION2
                    + END
            )

            self.sendMessage = packet

        except Exception as e:
            print(f"Error constructing DHCP packet: {e}")
            raise

    def decodePacket(self, data):
        """
        Decodes a raw DHCP packet (hex string) into human-readable fields.
        """
        try:
            message = ""

            # Header fields
            self.type = int(data[480:482], 16)
            self.xid = [data[8:10], data[10:12], data[12:14], data[14:16]]
            self.yiaddr = ".".join([str(int(data[32:40][i: i + 2], 16)) for i in range(0, 8, 2)])
            self.siaddr = ".".join([str(int(data[40:48][i: i + 2], 16)) for i in range(0, 8, 2)])
            self.macAddress = ":".join([data[56:68][i: i + 2] for i in range(0, 12, 2)])

            # Options
            options = data[472:]
            message += f"Type: {self.type}\n"
            position = 0

            while position < len(options):
                option_type = options[position: position + 2]
                if option_type == "ff":
                    break
                option_length = int(options[position + 2: position + 4], 16)
                option_data = options[position + 4: position + 4 + option_length * 2]

                if option_type == "33":  # Lease time
                    self.lease_time = int(option_data, 16)
                elif option_type == "0c":  # Hostname
                    self.hostname = bytearray.fromhex(option_data).decode()
                position += 4 + option_length * 2

            self.decoded = message

        except Exception as e:
            print(f"Error decoding DHCP packet: {e}")
            raise


if __name__ == "__main__":
    packet = DHCPPacket()
    packet.setMessage(
        type="02",
        transactionID=["12", "34", "56", "78"],
        client_mac_address="86:6b:d0:76:c7:b4",
        client_ip_address="192.168.100.2",
        server_ip_address="192.168.100.1",
        host_name="Client-1",
        lease_time=3600,
    )

    print(f"Packet to be sent: {packet.sendMessage}")
