# client.py

import socket
import struct

# Client configuration
SERVER_IP = "192.168.100.6"  # Localhost
SERVER_PORT = 67  # DHCP server port
CLIENT_PORT = 68  # DHCP client port


def main():
    # Create a UDP socket
    client_socket = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    client_socket.settimeout(5)  # Set timeout for waiting for server response

    # Create a generic request message to send
    test_message = b"Test client request for server response"

    try:
        # Send the message to the server
        client_socket.sendto(test_message, (SERVER_IP, SERVER_PORT))
        print("Request sent to server.")

        # Wait for the server's response
        data, server = client_socket.recvfrom(1024)
        print(f"Response from server: {data.decode()}")
    except socket.timeout:
        print("No response received from the server.")
    finally:
        # Close the socket
        client_socket.close()

if __name__ == "__main__":
    main()
