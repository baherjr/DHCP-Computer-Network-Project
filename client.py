import socket
from binascii import unhexlify, hexlify
from random import randint
from dhcp_packet import *
import sys
import random
import math
from datetime import *
import time


SERVER_PORT = 67
initial_interval = 10
backoff_cutoff = 120


class DHCPClient:
    def __init__(self, name, mac):
        self.hostname = name
        self.macAddress = mac
        self.ip = None
        self.ipReceivedTime = datetime.now()
        self.lease_time = 0
        self.response = None
        self.clientSocket = None
        self.timer = initial_interval
        self.elapsedTime = 0
        self.transactionID = []

        # Random transactionID
        for i in range(4):
            n = randint(0, 255)
            self.transactionID.append("{:02x}".format(n))

    def dhcpDiscover(self):
        print("Sending DHCP discovery")
        dest = ('<broadcast>', SERVER_PORT)
        discoverPacket = DHCPPacket()
        discoverPacket.setMessage(type="01", transactionID=self.transactionID, elapsed_ime=self.elapsedTime, client_mac_address=self.macAddress, host_name=self.hostname)
        self.clientSocket.sendto(unhexlify(discoverPacket.sendMessage), dest)

    def getResponse(self):
        data, addr = self.clientSocket.recvfrom(4096)
        packet = DHCPPacket()
        packet.decodePacket(hexlify(data).decode())
        self.response = packet

        if packet.type == 2:
            print("Received DHCP offer.")
        elif packet.type == 5:
            print("Received DHCP ack.")
        else:
            print("Received unrecognized packet.")

    def dhcpRequest(self):
        print("Sending DHCP request")
        dest = ('<broadcast>', SERVER_PORT)
        self.clientSocket.setsockopt(socket.SOL_SOCKET, socket.SO_BROADCAST, 1)
        discoverPacket = DHCPPacket()
        discoverPacket.setMessage(type="03", transactionID=self.transactionID, elapsed_ime=self.elapsedTime, client_mac_address=self.macAddress, host_name=self.hostname)
        self.clientSocket.sendto(unhexlify(discoverPacket.sendMessage), dest)

    def decodeIP(self, packet):
        received_ip = []
        for i in packet.yiaddr.split("."):
            received_ip.append(str(int(i, 16)))
        # Update received time, lease time and IP of client
        self.ipReceivedTime = datetime.now()
        self.lease_time = packet.lease_time
        self.ip = ".".join(received_ip)
        print("Received IP address: " + self.ip)
        print("Lease time = " + str(self.lease_time))
        print("*" * 25)


if __name__ == "__main__":
    if len(sys.argv) < 3:
        print("Error: Enter client MAC address and hostname.")
        exit(-1)

    client = DHCPClient(sys.argv[1], sys.argv[2])
    print("Initial timer = " + str(client.timer))
    print("*" * 25)

    with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as s:
        s.setsockopt(socket.SOL_SOCKET, socket.SO_BROADCAST, 1)
        client.clientSocket = s

        while True:
            if (datetime.now() - client.ipReceivedTime).seconds < client.lease_time:
                continue
            else:
                print("IP expired/Doesn't have IP.")
                print("Starting DHCP sequence.")
                print("*" * 25)
                time.sleep(2)
            client.dhcpDiscover()
            client.clientSocket.settimeout(client.timer)
            try:
                client.getResponse()
                if client.response.type == 2:
                    client.dhcpRequest()
                    client.getResponse()
                    client.decodeIP(client.response)
                elif client.response.type == 5:
                    client.decodeIP(client.response)
                client.elapsedTime = 0
                client.timer = initial_interval
            # Setting timer with formula P * 2 * R
            except socket.timeout:
                client.elapsedTime += client.timer
                client.timer = math.ceil(client.timer * random.uniform(0.5, 1) * 2)
                if client.timer > backoff_cutoff:
                    client.timer = backoff_cutoff
                print("Didn't receive response, current timer: " + str(client.timer))