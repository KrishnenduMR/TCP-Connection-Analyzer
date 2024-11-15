import tkinter as tk
from scapy.all import sniff, TCP, IP, conf
from datetime import datetime
import threading

class TCPScapyWindow:
    def __init__(self, root):
        self.root = root
        self.root.title("TCP Packet Analyzer")
        self.root.attributes('-fullscreen', True)  # Full-screen mode
        self.root.configure(bg="light blue")  # Consistent style

        # Bind Escape key to exit full-screen mode
        self.root.bind("<Escape>", self.exit_fullscreen)

        # Title Label
        self.title_label = tk.Label(
            self.root,
            text="TCP Packet Analyzer",
            font=("Arial", 20, "bold"),
            bg="light blue",
            fg="dark blue"
        )
        self.title_label.pack(pady=20)

        # Display area for packets
        self.output_area = tk.Text(
            self.root, wrap="word", height=25, width=90, font=("Courier", 10),
            bg="white", fg="black", borderwidth=2, relief="solid"
        )
        self.output_area.pack(pady=20, padx=20)

        # Control buttons frame
        self.button_frame = tk.Frame(self.root, bg="light blue")
        self.button_frame.pack(pady=10)

        # Start Button
        self.start_button = tk.Button(
            self.button_frame,
            text="Start Capture",
            width=15,
            font=("Arial", 12),
            bg="light green",
            fg="black",
            borderwidth=2,
            relief="solid",
            command=self.start_capture
        )
        self.start_button.pack(side="left", padx=20)

        # Stop Button
        self.stop_button = tk.Button(
            self.button_frame,
            text="Stop Capture",
            width=15,
            font=("Arial", 12),
            bg="light coral",
            fg="black",
            borderwidth=2,
            relief="solid",
            state="disabled",
            command=self.stop_capture
        )
        self.stop_button.pack(side="right", padx=20)

        # Exit Button
        self.exit_button = tk.Button(
            self.button_frame,
            text="Exit",
            width=10,
            font=("Arial", 12),
            bg="light gray",
            fg="black",
            borderwidth=2,
            relief="solid",
            command=self.exit_application
        )
        self.exit_button.pack(side="right", padx=20)

        # Handshake tracking
        self.handshakes = {}
        self.capturing = False

    def start_capture(self):
        """Start packet capturing in a new thread."""
        self.capturing = True
        self.start_button.config(state="disabled")
        self.stop_button.config(state="normal")
        self.capture_thread = threading.Thread(target=self.capture_packets)
        self.capture_thread.start()

    def stop_capture(self):
        """Stop packet capturing."""
        self.capturing = False
        self.start_button.config(state="normal")
        self.stop_button.config(state="disabled")

    def capture_packets(self):
        """Capture packets and process TCP three-way handshakes."""
        sniff(filter="tcp", prn=self.process_packet, store=False, stop_filter=lambda x: not self.capturing)

    def process_packet(self, packet):
        """Process each packet to detect and log TCP three-way handshake."""
        if packet.haslayer(TCP):
            tcp_layer = packet[TCP]
            ip_layer = packet[IP]
            timestamp = datetime.fromtimestamp(packet.time)

            # Handling SYN packet
            if tcp_layer.flags == 0x02:
                self.log_packet(packet, "SYN")
                key = (ip_layer.src, ip_layer.dst, tcp_layer.sport, tcp_layer.dport)
                self.handshakes[key] = {"SYN": packet.time}

            # Handling SYN-ACK packet
            elif tcp_layer.flags == 0x12:
                self.log_packet(packet, "SYN-ACK")
                key = (ip_layer.dst, ip_layer.src, tcp_layer.dport, tcp_layer.sport)
                if key in self.handshakes:
                    self.handshakes[key]["SYN-ACK"] = packet.time

            # Handling ACK packet
            elif tcp_layer.flags == 0x10:
                self.log_packet(packet, "ACK")
                key = (ip_layer.src, ip_layer.dst, tcp_layer.sport, tcp_layer.dport)
                if key in self.handshakes and "SYN-ACK" in self.handshakes[key]:
                    self.handshakes[key]["ACK"] = packet.time
                    self.log_handshake_complete(key)

    def log_packet(self, packet, flag_type):
        """Log packet details to the output area."""
        ip_layer = packet[IP]
        tcp_layer = packet[TCP]
        timestamp = datetime.fromtimestamp(packet.time)

        log_entry = (
            f"Packet Captured:\n"
            f"Timestamp: {timestamp}\n"
            f"Source IP: {ip_layer.src}, Destination IP: {ip_layer.dst}\n"
            f"Source Port: {tcp_layer.sport}, Destination Port: {tcp_layer.dport}\n"
            f"Flags: {flag_type}\n"
            "--------------------------------------------\n"
        )
        self.output_area.insert(tk.END, log_entry)
        self.output_area.see(tk.END)

    def log_handshake_complete(self, key):
        """Log the completion of a three-way handshake."""
        syn_time = datetime.fromtimestamp(self.handshakes[key]["SYN"])
        syn_ack_time = datetime.fromtimestamp(self.handshakes[key]["SYN-ACK"])
        ack_time = datetime.fromtimestamp(self.handshakes[key]["ACK"])

        handshake_log = (
            f"Three-Way Handshake Complete:\n"
            f"Connection: {key}\n"
            f"SYN Sent at: {syn_time}\n"
            f"SYN-ACK Sent at: {syn_ack_time}\n"
            f"ACK Sent at: {ack_time}\n"
            "============================================\n"
        )
        self.output_area.insert(tk.END, handshake_log)
        self.output_area.see(tk.END)

    def exit_fullscreen(self, event=None):
        """Exit full-screen mode when the Escape key is pressed."""
        self.root.attributes('-fullscreen', False)

    def exit_application(self):
        """Exit the application gracefully."""
        self.root.quit()  # Close the Tkinter application

# Initialize the GUI application
if __name__ == "__main__":
    root = tk.Tk()
    app = TCPScapyWindow(root)
    root.mainloop()
