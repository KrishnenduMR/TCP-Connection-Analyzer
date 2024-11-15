import tkinter as tk
import socket
import threading

class ServerWindow:
    def __init__(self, root):
        self.root = root
        self.root.title("Server - TCP Connection Analyzer")
        self.root.configure(bg="light blue")

        # Page Heading
        self.heading = tk.Label(
            self.root,
            text="SERVER - TCP CONNECTION ANALYZER",
            font=("Arial", 14, "bold"),
            bg="light blue",
            fg="dark blue"
        )
        self.heading.pack(pady=10)

        # Connection Status Label
        self.connection_label = tk.Label(
            self.root, 
            text="Server: Click 'Start Server' to listen for connections", 
            font=("Arial", 12), 
            bg="light blue"
        )
        self.connection_label.pack(pady=10)

        # Message Display Box
        self.msg_display = tk.Text(
            self.root,
            height=12,
            width=40,
            font=("Courier", 10),
            wrap=tk.WORD,
            borderwidth=2,
            relief="solid"
        )
        self.msg_display.pack(pady=10)

        # Buttons
        self.button_frame = tk.Frame(self.root, bg="light blue")
        self.button_frame.pack(pady=10)

        self.start_btn = tk.Button(
            self.button_frame,
            text="Start Server",
            command=self.start_server,
            font=("Arial", 12),
            width=15,
            bg="light grey",
            borderwidth=2,
            relief="solid"
        )
        self.start_btn.pack(side=tk.LEFT, padx=5)

        self.close_btn = tk.Button(
            self.button_frame,
            text="Close Connection",
            command=self.close_connection,
            font=("Arial", 12),
            width=15,
            bg="light grey",
            borderwidth=2,
            relief="solid"
        )
        self.close_btn.pack(side=tk.LEFT, padx=5)

        # Server Initialization
        self.server_socket = None
        self.client_conn = None
        self.connection_established = False

    def start_server(self):
        self.server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.server_socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        self.server_socket.bind(('localhost', 8090))
        self.server_socket.listen(1)
        self.connection_label.config(text="Server: Listening for Client...")
        threading.Thread(target=self.accept_client, daemon=True).start()

    def accept_client(self):
        try:
            self.client_conn, addr = self.server_socket.accept()
            self.connection_label.config(text=f"Connected to Client at {addr}")
            self.msg_display.insert(tk.END, "Connection initiated by Client\n")
            threading.Thread(target=self.handle_client, daemon=True).start()
        except Exception as e:
            self.connection_label.config(text=f"Error: {e}")

    def handle_client(self):
        try:
            while True:
                msg = self.client_conn.recv(1024).decode()
                if not msg:
                    break

                # Handshake Process
                if not self.connection_established:
                    if msg == "SYN":
                        self.msg_display.insert(tk.END, "SYN received from Client\n")
                        self.client_conn.send(b"SYN-ACK")
                        self.msg_display.insert(tk.END, "SYN-ACK sent to Client\n")
                    elif msg == "ACK":
                        self.msg_display.insert(tk.END, "ACK received from Client\n")
                        self.msg_display.insert(tk.END, "Connection fully established with Client\n")
                        self.connection_established = True
                else:
                    # Handle regular messages
                    if msg == "FIN":
                        self.msg_display.insert(tk.END, "FIN received, closing connection...\n")
                        self.client_conn.send(b"ACK")
                        break
                    else:
                        self.msg_display.insert(tk.END, f"Client: {msg}\n")
                        self.client_conn.send(b"ACK")
        except Exception as e:
            self.msg_display.insert(tk.END, f"Error: {e}\n")
        finally:
            self.client_conn.close()
            self.connection_label.config(text="Server: Waiting for Client...")
            self.connection_established = False

    def close_connection(self):
       self.msg_display.insert(tk.END, "Closing Server...\n")
       self.root.destroy()




# Initialize the GUI application
if __name__ == "__main__":
    root = tk.Tk()
    app = ServerWindow(root)
    root.mainloop()
