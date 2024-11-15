import tkinter as tk
from server import ServerWindow
from client import ClientWindow
from analyzer import AnalyzerWindow
# from usingscapy import TCPScapyWindow  # Uncomment if usingscapy module is available

class MainWindow:
    def __init__(self, root):
        self.root = root
        self.root.title("Main Window - TCP Connection Analyzer")
        self.root.attributes("-fullscreen", True)  # Make the window full screen
        self.root.configure(bg="light blue")

        # Page Heading
        self.heading = tk.Label(self.root, text="TCP CONNECTION ANALYZER", font=("Arial", 24, "bold"), bg="light blue", fg="dark blue")
        self.heading.pack(pady=100)

        # Center Frame for buttons
        self.center_frame = tk.Frame(self.root, bg="light blue")
        self.center_frame.place(relx=0.5, rely=0.5, anchor="center")  # Center the frame

        # Button configurations
        button_config = {"width": 20, "height": 2, "borderwidth": 3, "relief": "solid", "font": ("Arial", 14)}

        # Start Server Button
        self.server_btn = tk.Button(self.center_frame, text="Start Server", command=self.start_server, **button_config)
        self.server_btn.pack(pady=10)

        # Start Client Button
        self.client_btn = tk.Button(self.center_frame, text="Start Client", command=self.start_client, **button_config)
        self.client_btn.pack(pady=10)

        # Analyze pcap Button
        self.analyzer_btn = tk.Button(self.center_frame, text="Analyze pcap", command=self.start_analyzer, **button_config)
        self.analyzer_btn.pack(pady=10)

        # Analyze using scapy Button (Commented out)
        # self.scapy_btn = tk.Button(self.center_frame, text="Analyze using scapy", command=self.start_scapy, **button_config)
        # self.scapy_btn.pack(pady=10)

        # Exit Button
        self.exit_btn = tk.Button(self.center_frame, text="Exit", command=self.exit, **button_config)
        self.exit_btn.pack(pady=10)

    def start_server(self):
        # Create the server window
        server_root = tk.Toplevel(self.root)
        app = ServerWindow(server_root)

        # Get screen width and height to position the windows side by side
        screen_width = self.root.winfo_screenwidth()
        screen_height = self.root.winfo_screenheight()

        # Position the server window on the right side (horizontally) and vertically centered
        server_root.geometry(f"500x400+{screen_width//2+200}+{(screen_height-400)//2}")  
        server_root.lift()  # Bring the server window to the front
        server_root.focus_force()  # Ensure the window stays in focus

    def start_client(self):
        # Withdraw the main window when the client window is opened
        self.root.withdraw()

        # Create the client window
        client_root = tk.Toplevel(self.root)
        app = ClientWindow(client_root)

        # Get screen width and height to position the windows side by side
        screen_width = self.root.winfo_screenwidth()
        screen_height = self.root.winfo_screenheight()

        # Position the client window on the left side (horizontally) and vertically centered
        client_root.geometry(f"500x400+{screen_width//2 - 700}+{(screen_height-400)//2}")  
        client_root.lift()  # Bring the client window to the front
        client_root.focus_force()  # Ensure the window stays in focus

        # When the client window is closed, show the main window again
        client_root.bind("<Destroy>", self.on_client_close)

    def on_client_close(self, event=None):
        # Show the main window again
        self.root.deiconify()

    def start_analyzer(self):
        self.root.withdraw()  # Hide main window
        analyzer_root = tk.Toplevel(self.root)
        app = AnalyzerWindow(analyzer_root)
        analyzer_root.wait_window()  # Wait until the analyzer window is closed
        self.root.deiconify()  # Show the main window again after analyzer window is closed

    # Start Scapy Analyzer Function (Commented out)
    # def start_scapy(self):
    #     self.root.withdraw()  # Hide
    #     scapy_root = tk.Toplevel(self.root)
    #     app = TCPScapyWindow(scapy_root)
    #     scapy_root.wait_window()  # Wait until the scapy window is closed
    #     self.root.deiconify()  # Show the main window again after scapy window is closed
    #     scapy_root.mainloop()

    def exit(self):
        self.root.destroy()  

# Initialize Main Window
if __name__ == "__main__":
    root = tk.Tk()
    app = MainWindow(root)
    root.mainloop()
