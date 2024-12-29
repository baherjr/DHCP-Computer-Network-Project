import socket
from binascii import unhexlify, hexlify
from dhcp_packet import *
import threading
import json
from ipaddress import *
from datetime import *
import time


SERVER_PORT = 67
SERVER_IP = "192.168.1.1"

serverSocket = None
ip_range_start = ""
ip_range_finish = ""
lease_time = 0
ip_pool = []
reservation_list = {}
black_list = []
accepted_clients = []


def readConfigs():
    with open("F:/ASU/YEAR 4/Semester 1/CSE351 - Networks/Project/Networks/configs.json") as file:
        global ip_range_start
        global ip_range_finish
        global ip_pool
        global reservation_list
        global black_list
        global lease_time
        global SERVER_IP

        configs = json.load(file)
        pool_mode = configs.get("pool_mode")

        if pool_mode == "range":
            ip_range = configs.get("range")
            ip_range_start = IPv4Address(ip_range.get("from"))
            ip_range_finish = IPv4Address(ip_range.get("to"))
            start = ip_range_start
            while start <= ip_range_finish:
                ip_pool.append(start)
                start += 1
            SERVER_IP = str(ip_pool.pop(0))

        elif pool_mode == "subnet":
            ip_range = configs.get("subnet")
            subnet_mask = ip_range.get("subnet_mask")
            ip_range_start = IPv4Address(ip_range.get("ip_block"))
            ips = list(ip_network(str(ip_range_start) + "/" + subnet_mask, strict=False))
            ip_range_start += 1
            ip_range_finish = ips[-2]
            for i in ips:
                if ip_range_start <= i <= ip_range_finish:
                    ip_pool.append(i)
            SERVER_IP = str(ip_pool.pop(0))

        else:
            print("Error: could not read configs.json")
            exit(-1)

        lease_time = configs.get("lease_time")
        reservation_list = configs.get("reservation_list")
        black_list = configs.get("black_list")

        # Modified section to handle reservation list
        for key, value in reservation_list.items():
            reserved_ip = IPv4Address(value)
            if reserved_ip in ip_pool:
                ip_pool.remove(reserved_ip)

        print("*" * 25)
        print("Configs are set.")
        print("*" * 25)


def isBlocked(mac):
    for i in black_list:
        if mac == i:
            return True
    return False


def isReserved(mac):
    if reservation_list.get(mac) is not None:
        return True
    return False


def isAccepted(mac):
    for i in accepted_clients:
        if i[1] == mac:
            return True
    return False


def getOfferIP():
    if len(ip_pool) == 0:
        return None
    return ip_pool.pop(0)


def addToAccepted(host_name, mac, ip):
    accepted_clients.append([host_name, mac, ip, datetime.now()])


def dhcpOffer(address, packet, offer_ip):
    print("Sending DHCP offer to: " + packet.macAddress)
    offerPacket = DHCPPacket()
    offerPacket.setMessage(type="02", transactionID=packet.xid, client_mac_address=packet.macAddress, client_ip_address=offer_ip, server_ip_address=SERVER_IP, lease_time=lease_time)
    print("Packet to be sent: " + json.dumps(offerPacket.__dict__, indent=4))
    serverSocket.sendto(unhexlify(offerPacket.sendMessage), address)


def dhcpAck(address, packet, client_ip):
    print("Sending DHCP ack to: " + packet.macAddress)
    print("*" * 25)
    ackPacket = DHCPPacket()
    ackPacket.setMessage(type="05", transactionID=packet.xid, client_mac_address=packet.macAddress, client_ip_address=client_ip, server_ip_address=SERVER_IP, lease_time=lease_time)
    serverSocket.sendto(unhexlify(ackPacket.sendMessage), address)


def clientThread(address, data):
    packet = DHCPPacket()
    packet.decodePacket(hexlify(data).decode())

    if packet.type == 1:
        print("Received DHCP discovery from MAC: " + packet.macAddress)
    elif packet.type == 3:
        print("Received DHCP request from MAC: " + packet.macAddress)

    if isBlocked(packet.macAddress):
        print("MAC address " + packet.macAddress + " is blocked.")
        print("*" * 25)
    elif isReserved(packet.macAddress):
        print("MAC address " + packet.macAddress + " has reserved IP.")
        dhcpAck(address, packet, reservation_list.get(packet.macAddress))
    elif isAccepted(packet.macAddress) and packet.type == 1:
        print("MAC address " + packet.macAddress + " is already accepted")
        print("Timer set back to default.")
        for entry in accepted_clients:
            if packet.macAddress == entry[1]:
                entry[3] = datetime.now()
                dhcpAck(address, packet, entry[2])
                break
    else:
        # discover message
        if packet.type == 1:
            offer_ip = str(getOfferIP())
            if offer_ip != "None":
                addToAccepted(packet.hostname, packet.macAddress, offer_ip)
                dhcpOffer(address, packet, offer_ip)
        # request message
        elif packet.type == 3:
            found = 0
            for entry in accepted_clients:
                if packet.macAddress == entry[1]:
                    found = 1
                    dhcpAck(address, packet, entry[2])
                    break
            if found == 0:
                print("MAC address not in accepted list." + packet.macAddress)
                print("*" * 25)


def printStatus():
    print("~" * 25)
    print("Accepted clients:")
    current_time = datetime.now()
    for entry in accepted_clients:
        print(entry[0] + " - " + entry[1] + " - " + entry[2] + " - " + str(lease_time - (current_time - entry[3]).seconds))
    print("~" * 25)


def printReservation():
    print("~" * 25)
    print("Reserved clients:")
    for key, value in reservation_list.items():
        print(key + " = " + value)
    print("~" * 25)


def printBlackList():
    print("~" * 25)
    print("Black listed clients:")
    for entry in black_list:
        print(entry)
    print("~" * 25)


def printPool():
    print("~" * 25)
    print("IP Pool:")
    for entry in ip_pool:
        print(entry)
    print("~" * 25)


def statusThread():
    while True:
        command = input()
        if command == "show_clients":
            printStatus()
        elif command == "show_res":
            printReservation()
        elif command == "show_bl":
            printBlackList()
        elif command == "show_ip":
            printPool()


def updateAcceptedList():
    remove = []
    for i in accepted_clients:
        if (datetime.now() - i[3]).seconds > lease_time:
            remove.append(accepted_clients.index(i))
    for i in remove:
        rm = accepted_clients.pop(i)
        print("MAC address: " + rm[1] + " with ip: " + rm[2] + " expired")
        ip_pool.insert(0, rm[2])
    if len(remove) != 0:
        print("*" * 25)


def timerThread():
    while True:
        updateAcceptedList()
        time.sleep(0.01)


if __name__ == "__main__":
    readConfigs()
    print("Server is listening")
    print("*" * 25)

    # Keeping the TimerThread and StatusThread as they are
    statusT = threading.Thread(target=statusThread)
    timeT = threading.Thread(target=timerThread)
    statusT.start()
    timeT.start()

    with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as server:
        server.setsockopt(socket.SOL_SOCKET, socket.SO_BROADCAST, 1)
        server.bind(('', SERVER_PORT))
        serverSocket = server

        while True:
            data, addr = server.recvfrom(4096)

            clientThread(addr, data)
