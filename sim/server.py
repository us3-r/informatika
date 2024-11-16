import socket
import threading

clients = []  # List of connected client sockets
public_keys = {}  # Map client sockets to their public keys


def handle_client(client_socket, client_address):
    """
    Handle communication with a single client.
    """
    print(f"New connection from {client_address}")
    clients.append(client_socket)

    try:
        # Receive the public key from the client
        public_key = client_socket.recv(1024).decode()
        print(f"Received public key from {client_address}")
        public_keys[client_socket] = public_key

        # Send the public key of the new client to all other clients
        for client in clients:
            if client != client_socket:
                client.sendall(f"{client_address}: {public_key}".encode())

        # Send the public keys of all existing clients to the new client
        for client, key in public_keys.items():
            if client != client_socket:
                client_socket.sendall(f"{client.getpeername()}: {key}".encode())

        # Handle incoming messages from the client
        while True:
            message = client_socket.recv(1024)
            if not message:
                break  # Client disconnected

            # Broadcast the message to all other clients
            for client in clients:
                if client != client_socket:
                    client.sendall(message)

    except ConnectionResetError:
        print(f"Client {client_address} disconnected")
    finally:
        clients.remove(client_socket)
        del public_keys[client_socket]
        client_socket.close()


def server_program():
    """
    Start the server and accept multiple client connections.
    """
    server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server_socket.bind(('127.0.0.1', 5000))
    server_socket.listen()

    print("Server is running and waiting for connections...")
    try:
        while True:
            client_socket, client_address = server_socket.accept()
            client_thread = threading.Thread(target=handle_client, args=(client_socket, client_address))
            client_thread.start()

    except KeyboardInterrupt:
        print("Shutting down server...")


server_program()
