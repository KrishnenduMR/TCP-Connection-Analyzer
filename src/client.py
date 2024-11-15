import tkinter as tk
import socket
import threading

class ClientWindow:
    def __init__(self, root):
        self.root = root
        self.root.title("Client - TCP Connection Analyzer")
        self.root.configure(bg="light blue")

        # Page Heading
        self.heading = tk.Label(
            self.root,
            text="CLIENT - TCP CONNECTION ANALYZER",
            font=("Arial", 14, "bold"),
            bg="light blue",
            fg="dark blue"
        )
        self.heading.pack(pady=10)

        # Connection Status Label
        self.connection_label = tk.Label(
            self.root, 
            text="Client: Click 'Start Connection' to initiate handshake", 
            font=("Arial", 12), 
            bg="light blue"
        )
        self.connection_label.pack(pady=10)

        # Message Entry
        self.msg_entry = tk.Entry(self.root, width=40, font=("Arial", 12), borderwidth=2, relief="solid")
        self.msg_entry.pack(pady=10)

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

        # Buttons Frame
        self.button_frame = tk.Frame(self.root, bg="light blue")
        self.button_frame.pack(pady=5)

        # Start Connection Button
        self.start_btn = tk.Button(
            self.button_frame,
            text="Start Connection",
            command=self.start_connection,
            font=("Arial", 12),
            width=15,
            bg="light grey",
            borderwidth=2,
            relief="solid"
        )
        self.start_btn.pack(side=tk.LEFT, padx=5)

        # Send Button
        self.send_btn = tk.Button(
            self.button_frame,
            text="Send",
            command=self.send_message,
            font=("Arial", 12),
            width=15,
            bg="light grey",
            borderwidth=2,
            relief="solid",
            state=tk.DISABLED  # Initially disabled
        )
        self.send_btn.pack(side=tk.LEFT, padx=5)

        # Close Connection Button
        self.close_btn = tk.Button(
            self.button_frame,
            text="Close Connection",
            command=self.close_connection,
            font=("Arial", 12),
            width=15,
            bg="light grey",
            borderwidth=2,
            relief="solid",
            state=tk.DISABLED  # Initially disabled
        )
        self.close_btn.pack(side=tk.LEFT, padx=5)

        # Client Socket Initialization
        self.client_socket = None
        self.connection_established = False

    def start_connection(self):
        try:
            self.client_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            self.client_socket.connect(('localhost', 8090))  # Connect to the server
            self.connection_label.config(text="Client: Connected to Server")
            self.msg_display.insert(tk.END, "Connection initiated with Server\n")

            # Start Handshake
            threading.Thread(target=self.perform_handshake, daemon=True).start()
        except Exception as e:
            self.connection_label.config(text=f"Error: {e}")

    def perform_handshake(self):
        try:
            # Send SYN
            self.client_socket.send(b"SYN")
            self.msg_display.insert(tk.END, "SYN sent to Server\n")
            
            # Wait for SYN-ACK
            syn_ack = self.client_socket.recv(1024).decode()
            if syn_ack == "SYN-ACK":
                self.msg_display.insert(tk.END, "SYN-ACK received from Server\n")
                # Send ACK
                self.client_socket.send(b"ACK")
                self.msg_display.insert(tk.END, "ACK sent to Server\n")
                self.msg_display.insert(tk.END, "Connection fully established with Server\n")
                self.connection_established = True

                # Enable other buttons
                self.send_btn.config(state=tk.NORMAL)
                self.close_btn.config(state=tk.NORMAL)
        except Exception as e:
            self.msg_display.insert(tk.END, f"Error during handshake: {e}\n")

    def send_message(self):
        msg = self.msg_entry.get()
        if msg:
            self.client_socket.send(msg.encode())
            self.msg_display.insert(tk.END, f"You: {msg}\n")
            self.msg_entry.delete(0, tk.END)  # Clear the message entry

    def close_connection(self):
        self.msg_display.insert(tk.END, "Connection closed with Server\n")
        self.running = False

# Initialize the GUI application
if __name__ == "__main__":
    root = tk.Tk()
    app = ClientWindow(root)
    root.mainloop()
