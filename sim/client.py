import socket
import threading
import argparse
from utils_sim import CHelper, EncryptionHandler, DecryptionHandler, FileHandler

CHelper = CHelper()
# create 1 flag to set name
arg_parser = argparse.ArgumentParser(description='Set name for chat',
                                     formatter_class=argparse.RawTextHelpFormatter)

arg_parser.add_argument('-n', '--name', type=str, metavar='str')
arg_parser.add_argument('-k', '--key', type=str, metavar='path/to/key', )
arg_parser.add_argument('-s', '--secret', type=str, metavar='str')

_arg = arg_parser.parse_args()
_name = _arg.name
_key = _arg.key
_secret = _arg.secret

# set private key
k = _key.replace('public', 'private')

decryption_handler = DecryptionHandler(
    key_path=k,
    secret=_secret,
    verbose=True
)

encryption_handler = EncryptionHandler(
    key_path=_key,
    secret=_secret,
    verbose=True
)


def receive_messages(client_socket):
    """
    Continuously listen for messages from the server.
    """
    while True:
        try:
            message = client_socket.recv(1024)
            if not message:
                break

            # Distinguish between public key updates and regular messages
            decoded_message = message.decode()
            if ":" in decoded_message:  # Public key update (format: "<address>: <public_key>")
                address, public_key = decoded_message.split(": ", 1)
                print(f"[KEY] Public key from {address}: {public_key}")
            else:
                print(f"---> {decoded_message}")
                print(decryption_handler.decrypt_text(decoded_message, False, 'RSA'))

        except ConnectionResetError:
            print("Disconnected from server")
            break


def client_program():
    """
    Connect to the server and enable live chat.
    """
    client_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    client_socket.connect(('127.0.0.1', 5000))

    # send public key to server
    if _key:
        public_key = FileHandler.read_file(_key)
        client_socket.send(public_key.encode())

    # Start a thread for receiving messages
    receive_thread = threading.Thread(target=receive_messages, args=(client_socket,))
    receive_thread.start()

    print(
        "+-------------------------------------------------------+\n" +
        "| This is a sample client for simulating a chat program  \n" +
        "| with P2P encrypted communication.                     \n" +
        "| Type 'exit' to quit the chat.                          \n" +
        "+-------------------------------------------------------+"
    )

    # Main loop for sending messages
    try:
        while True:
            message = input("(You)")  # Get user input
            if message.lower() == "exit":
                break
            clear_msg = f"\n{message}"

            enc_data = encryption_handler.encrypt_text(message, False, 'RSA')
            client_socket.sendall(enc_data)
    except KeyboardInterrupt:
        print("Exiting chat...")
    finally:
        client_socket.close()


client_program()
