#!/usr/bin/env python3


import sys, os
import argparse
import socket
import threading
import ssl
import tkinter as tk


# Set up window
root = tk.Tk()
root.title('LAN Events Monitor')

text_widget = tk.Text(root)
text_widget.pack(fill=tk.BOTH, expand=True)
text_widget.pack_propagate(False)

thread_count = 0        # Track number of threads/clients
connected_clients = []  # Stores clients


def parse_args():
    # Parse command line args
    parser = argparse.ArgumentParser()

    parser.add_argument("-p",
                        "--port",
                        type=int,
                        help="Port that this application will listen on",
                        required=True)

    args = parser.parse_args()

    return args


def create_ssl_socket(socket_):
    certfile = 'certs/domain.crt'
    keyfile = 'certs/domain.key'

    context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    context.load_cert_chain(certfile, keyfile)

    secure_socket = context.wrap_socket(socket_, server_side=True)
    secure_socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    # secure_socket.setblocking(0)

    return secure_socket


def handle_client(socket):
    global thread_count
    socket.send(str.encode(f"Connected to {socket.getsockname()}"))

    while True:
        try:
            data = socket.recv(4096)
        except:
            print("No data from client")

        if data:
            remote_client = socket.getpeername()[0]
            # print(f'{remote_client} :: {data.decode("utf-8")}')
            text_widget.insert(tk.END, f'{remote_client} :: {data.decode("utf-8")}\n')
            text_widget.see(tk.END)

        if not data:
            thread_count -= 1
            connected_clients.remove(socket)
            # print(f"{socket.getpeername()[0]} :: disconnected, {thread_count} current client(s)")
            text_widget.insert(tk.END, f"{socket.getpeername()[0]} :: disconnected, {thread_count} current client(s)\n")
            text_widget.see(tk.END)
            break

    socket.close()


def start_server():
    # Parse arguments
    args = parse_args()

    # Server setup
    socket_ = socket.socket()

    # Wrap socket in SSL wrapper
    global secure_socket
    secure_socket = create_ssl_socket(socket_)

    host = ""
    port = args.port
    global thread_count

    try:
        secure_socket.bind((host, port))
    except socket.error as e:
        print(str(e))
    
    secure_socket.listen()
    # print(f"Listening on port {port}...")
    text_widget.insert(tk.END, f"Listening on port {port}...\n")
    text_widget.see(tk.END)

    # Accept incoming connections
    while True:
        try:
            client, addr = secure_socket.accept()
            connected_clients.append(client)
            thread_count += 1
            # print(f"{addr[0]} :: connected, {thread_count} current client(s)")
            text_widget.insert(tk.END, f"{addr[0]} :: connected, {thread_count} current client(s)\n")
            text_widget.see(tk.END)
            
            threading.Thread(target=handle_client, args=(client, )).start()
        except KeyboardInterrupt:
            print("Keyboard interrupt")
            secure_socket.close()
            break

    secure_socket.close()
    os._exit(0)


def start_server_thread():
    # Disable button once server starts
    start_button.config(state='disabled')

    server_thread = threading.Thread(target=start_server)
    server_thread.start()


def stop_server():
    try:
        secure_socket.close()
    except:
        pass

    for client in connected_clients:
        client.send('$SHUTDOWN'.encode('utf-8'))

    root.destroy()
    os._exit(0)


def main():
    global start_button
    start_button = tk.Button(root, text="Start Server", command=start_server_thread)
    start_button.pack()

    stop_button = tk.Button(root, text="Stop Server", command=stop_server)
    stop_button.pack()

    root.protocol('WM_DELETE_WINDOW', stop_server)

    root.mainloop()


if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        print("Exiting program...")
        sys.exit()
