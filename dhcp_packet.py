class DHCPPacket:
    def __init__(self):
        self.type = 0
        self.xid = []
        self.macAddress = ""
        self.yiaddr = ""
        self.siaddr = ""
        self.hostname = ""
        self.lease_time = 0
        self.sendMessage = ""
        self.decoded = ""

    # Type:
    # Discover = 01
    # Offer = 02 For Server
    # Request = 03
    # Ack = 04 For Server
    def setMessage(self, type, transactionID, client_mac_address, elapsed_ime=0, client_ip_address="0.0.0.0", server_ip_address="0.0.0.0", host_name="", lease_time=0):
        if type == "01" or type == "03":
            OP = "01"
        else:
            OP = "02"
        HTYPE = "01"
        HLEN = "06"
        HOPS = "00"
        XID = ""
        for i in transactionID:
            XID += i
        if elapsed_ime == 0:
            SECS = "00" * 2
        else:
            SECS = "{:04x}".format(int(elapsed_ime))
        FLAGS = "00" * 2
        CIADDR = "00" * 4
        YIADDR = ""
        for i in client_ip_address.split("."):
            YIADDR += "{:02x}".format(int(i))
        SIADDR = ""
        for i in server_ip_address.split("."):
            SIADDR += "{:02x}".format(int(i))
        GIADDR = "00" * 4
        CHADDR = ""
        for i in client_mac_address.split(":"):
            CHADDR += i
        for i in range(10):
            CHADDR += "{:02x}".format(0)
        SNAME = "00" * 64
        FILE = "00" * 128
        MAGICCOOKIE = ""  # DHCP
        for i in ["63", "82", "53", "63"]:
            MAGICCOOKIE += i
        OPTION1 = ""  # Message Type
        for i in ["35", "01", type]:
            OPTION1 += i
        OPTION2 = ""
        if host_name != "":
            OPTION2 = "0c"
            OPTION2 += "{:02x}".format(len(host_name))
            for i in host_name:
                OPTION2 += "{:02x}".format(ord(i))
        elif lease_time != 0:
            OPTION2 = "33"
            OPTION2 += "04"
            lease_time_str = hex(lease_time).split('x')[-1]
            for i in range(0, 8 - len(lease_time_str)):
                OPTION2 += "0"
            OPTION2 += lease_time_str

        END = "ff"  # End of Options

        packet = ""
        packet += OP
        packet += HTYPE
        packet += HLEN
        packet += HOPS
        packet += XID
        packet += SECS
        packet += FLAGS
        packet += CIADDR
        packet += YIADDR
        packet += SIADDR
        packet += GIADDR
        packet += CHADDR
        packet += SNAME
        packet += FILE
        packet += MAGICCOOKIE
        packet += OPTION1
        packet += OPTION2
        packet += END

        self.sendMessage = packet

    def decodePacket(self, data):
        message = ""

        OP = data[0:2]
        HTYPE = data[2:4]
        HLEN = data[4:6]
        HOPS = data[6:8]
        XID = data[8:16]
        SECS = data[16:20]
        FLAGS = data[20:24]
        CIADDR = data[24:32]
        YIADDR = data[32:40]
        SIADDR = data[40:48]
        GIADDR = data[48:56]
        CHADDR = data[56:88]
        SNAME = data[88:216]
        FILE = data[216:472]
        MAGICCOOCKIE = data[472:480]
        OPTION1 = data[480:486]
        option2_len = 0
        OPTION2 = ""
        if data[486:488] != "ff":
            option2_len = int(data[488:490], 16)
            OPTION2 = data[486:486 + 4 + option2_len * 2]

        message += "OP: "
        message += OP
        message += "\nHTYPE: "
        message += HTYPE
        message += "\nHLEN: "
        message += HLEN
        message += "\nHOPS: "
        message += HOPS
        message += "\nXID: "
        message += XID
        message += "\nSECS: "
        message += SECS
        message += "\nFLAGS: "
        message += FLAGS
        message += "\nCIADDR: "
        message += CIADDR
        message += "\nYIADDR: "
        message += YIADDR
        message += "\nSIADDR: "
        message += SIADDR
        message += "\nGIADDR: "
        message += GIADDR
        message += "\nCHADDR: "
        message += CHADDR
        message += "\nSNAME: "
        message += SNAME
        message += "\nFILE: "
        message += FILE
        message += "\nMAGIC-COOCKIE: "
        message += MAGICCOOCKIE
        message += "\nOPTION1: "
        message += OPTION1
        message += "\nOPTION2: "
        message += OPTION2
        message += "\n"

        # XID
        for i in range(4):
            self.xid.append(XID[i * 2:i * 2 + 2])
        # Client IP
        for i in range(4):
            self.yiaddr += YIADDR[i * 2:i * 2 + 2]
            if i != 3:
                self.yiaddr += "."
        # Server IP
        for i in range(4):
            self.siaddr += SIADDR[i * 2:i * 2 + 2]
            if i != 3:
                self.siaddr += "."
        # DHCP message type
        self.type = int(OPTION1[4:], 16)
        # Client MAC address
        for i in range(6):
            self.macAddress += CHADDR[i * 2:i * 2 + 2]
            if i != 5:
                self.macAddress += ":"
        # Hostname
        if OPTION2[0:2] == "33":
            lease_time_str = ""
            for i in range(0, option2_len):
                lease_time_str += OPTION2[4 + (i * 2):6 + (i * 2)]
            self.lease_time = int(lease_time_str, 16)
        elif OPTION2[0:2] == "0c":
            for i in range(0, option2_len):
                self.hostname += chr(int(OPTION2[4 + (i * 2): 6 + (i * 2)], 16))
            # Decoded packet
        self.decoded = message


if __name__ == '__main__':
    pass