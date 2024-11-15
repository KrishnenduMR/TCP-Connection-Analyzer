import tkinter as tk
from tkinter import filedialog
import pyshark

class AnalyzerWindow:
    def __init__(self, root):
        self.root = root
        self.root.title("TCP Connection Analyzer - pcap")
        self.root.attributes("-fullscreen", True)  # Full-screen mode
        self.root.configure(bg="light blue")

        # Page Heading
        self.heading = tk.Label(
            self.root, 
            text="TCP CONNECTION ANALYZER - PCAP", 
            font=("Arial", 24, "bold"), 
            bg="light blue", 
            fg="dark blue"
        )
        self.heading.pack(pady=20)

        # Top Frame for buttons
        self.button_frame = tk.Frame(self.root, bg="light blue")
        self.button_frame.pack(pady=10)

        # Button configurations
        button_config = {
            "width": 20,
            "height": 2,
            "borderwidth": 3,
            "relief": "solid",
            "font": ("Arial", 14),
        }

        # Load pcap Button
        self.load_btn = tk.Button(
            self.button_frame, text="Load pcap File", command=self.load_pcap, **button_config
        )
        self.load_btn.pack(side=tk.LEFT, padx=10)

        # Back to Main Button
        self.exit_btn = tk.Button(
            self.button_frame, text="Back to Main", command=self.exit_to_main, **button_config
        )
        self.exit_btn.pack(side=tk.LEFT, padx=10)

        # Text widget to display packet analysis
        self.analysis_display = tk.Text(
            self.root,
            font=("Courier", 12),  # Monospaced font for better readability
            wrap=tk.WORD,
            borderwidth=3,
            relief="solid",
        )
        self.analysis_display.pack(expand=True, fill=tk.BOTH, padx=20, pady=20)

    def load_pcap(self):
        # Open file dialog to select a pcap file
        self.pcap_file = filedialog.askopenfilename(filetypes=[("pcap Files", "*.pcap")])
        if self.pcap_file:
            self.analyze_pcap()

    def analyze_pcap(self):
        # Clear the previous analysis
        self.analysis_display.delete(1.0, tk.END)
        
        # Open the pcap file using PyShark and apply filter for TCP packets
        cap = pyshark.FileCapture(self.pcap_file, display_filter="tcp.port == 8090")  # filter for port 8090

        # List to store packets along with their timestamps
        packets = []

        # Iterate through packets and capture those with TCP protocol
        for packet in cap:
            if 'TCP' in packet:
                packets.append(packet)

        # Sort packets by timestamp to ensure the correct order
        packets.sort(key=lambda x: float(x.sniff_time.timestamp()))

        # Display the packets sorted by time
        for packet in packets:
            if 'TCP' in packet:
                self.display_packet_info(packet)

    def display_packet_info(self, packet):
        # Map of flag hex values to TCP flag names
        flag_map = {
            "0x0002": "SYN",
            "0x0012": "SYN-ACK",
            "0x0010": "ACK",
            "0x0018": "ACK + PSH",
            "0x0014": "SYN-ACK + PSH",
        }

        # Get flag value in hexadecimal format
        flag_hex = f"{packet.tcp.flags}"

        # Map the flag hex value to its English meaning
        flag_meaning = flag_map.get(flag_hex, "Unknown Flag")

        # Show packet details for each TCP packet
        self.analysis_display.insert(tk.END, f"Packet: {packet.number}\n")
        self.analysis_display.insert(tk.END, f"Timestamp: {packet.sniff_time}\n")
        self.analysis_display.insert(tk.END, f"Source IP: {packet.ip.src}, Destination IP: {packet.ip.dst}\n")
        self.analysis_display.insert(tk.END, f"Source Port: {packet.tcp.srcport}, Destination Port: {packet.tcp.dstport}\n")
        self.analysis_display.insert(tk.END, f"Sequence Number: {packet.tcp.seq}, Acknowledgment Number: {packet.tcp.ack}\n")
        self.analysis_display.insert(tk.END, f"Flags (Hex): {flag_hex} ({flag_meaning})\n")
        self.analysis_display.insert(tk.END, "--------------------------------------------------\n")

    def exit_to_main(self):
        self.root.destroy()  # Close the analyzer window to return to the main window

# Initialize the Analyzer Window when the script is executed
if __name__ == "__main__":
    root = tk.Tk()
    app = AnalyzerWindow(root)
    root.mainloop()
