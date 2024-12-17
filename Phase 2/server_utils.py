import socket
import binascii

# Server configuration
SERVER_PORT = 67  # Port for the DHCP server
BROADCAST_ADDRESS = "255.255.255.255"


def main():
    # Create a UDP socket
    server_socket = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)

    # Enable broadcast
    server_socket.setsockopt(socket.SOL_SOCKET, socket.SO_BROADCAST, 1)

    # Bind to all interfaces (0.0.0.0) and port 67
    server_socket.bind(("0.0.0.0", SERVER_PORT))
    print(f"Server is running and listening on all interfaces (port {SERVER_PORT})")

    while True:
        try:
            # Wait for a message from the client
            data, client_address = server_socket.recvfrom(1024)
            print(f"Received message from {client_address}: {binascii.hexlify(data).decode()}")

            # Check if the client address is invalid (0.0.0.0)
            if client_address[0] == "0.0.0.0":
                print(f"Client has no valid IP address. Broadcasting response to the network.")
                # Send the response via broadcast
                response_message = b"DHCP server response"
                server_socket.sendto(response_message, (BROADCAST_ADDRESS, client_address[1]))
            else:
                # Normally response to the specific client
                response_message = b"Test server response to your request"
                server_socket.sendto(response_message, client_address)
                print(f"Response sent to {client_address}")

        except OSError as e:
            # Handle errors related to the socket
            print(f"Socket error occurred: {e}")
        except Exception as e:
            # Handle unforeseen errors
            print(f"An unexpected error occurred: {e}")


if __name__ == "__main__":
    main()