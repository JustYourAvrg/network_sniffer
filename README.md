# Network Sniffer

This is a Python-based Packet Sniffer application with a GUI built using CustomTkinter. It allows you to capture and analyze network packets, display protocol data, and perform IP lookups.

## Features

- **Packet Sniffer**: Capture network packets on a specified interface.
- **Protocol Filter**: Filter captured packets by protocol (TCP, UDP, or None).
- **IP Lookup**: Retrieve and display geolocation information for IP addresses.
- **Data Visualization**: Display captured protocol data using a pie chart.
- **Multi-threading**: Perform sniffing and data updating in background threads.

## Requirements

- Python 3.11 or greater
- `customtkinter` library
- `scapy` library
- `matplotlib` library
- `winsound` library (for Windows)
- Other custom modules and utilities from the `app` directory

## Installation

1. Clone the repository:
    ```bash
    git clone https://github.com/JustYourAvrg/network_sniffer.git
    cd network_sniffer
    ```

2. Install the required Python libraries:
     the libraries should install when you run the main.py file

3. Ensure the following custom modules are present in the `app` directory:
    - `app.sniffer.SnifferClass`
    - `app.setup.Setup`
    - `app.Gui.messagebox.MessageBox`
    - `app.Gui.utils`

## Usage

1. Run the application:
    ```bash
    python main.py
    ```

2. Use the interface selector to choose a network interface for packet sniffing.

3. Use the protocol filter to select the protocol you want to filter (TCP, UDP, or None).

4. Click "Start Sniffing" to begin capturing packets.

5. Switch between frames using the buttons in the top bar:
    - **Sniffer**: Display captured packets.
    - **Lookup**: Perform IP lookups and display geolocation data.
    - **Data**: Display protocol data in a pie chart.

## Code Overview

### Main Components

- **GuiFramesAndUtility**: Manages GUI frames, sniffing operations, and data updates.
- **SnifferClass**: Handles packet capturing and error checking.
- **Setup**: Imports required modules.
- **MessageBox**: Displays error messages.
- **Utilities**: Provides helper functions for interface selection, frame creation, and data retrieval.

### Functions

- `set_iface(iface)`: Sets the network interface for sniffing.
- `set_proto(proto)`: Sets the protocol filter.
- `frame_swap(frame, frame_btn, all_buttons)`: Switches between different GUI frames.
- `sniffer_frame_func()`: Creates the sniffer frame.
- `lookup_frame_func()`: Creates the lookup frame.
- `ip_lookup_command(ip)`: Performs IP lookup and displays geolocation data.
- `data_frame_func()`: Creates the data frame.
- `create_graph()`: Creates a pie chart for protocol data.
- `update_data()`: Updates data for the data frame.
- `start_data_thread()`: Starts the data updating thread.
- `start_sniffing_thread()`: Starts the packet sniffing thread.
- `start_sniffing()`: Captures packets and updates the sniffer display.
- `update_sniffer_displays(packets)`: Updates the sniffer display with captured packets.
- `stop_sniffing()`: Stops the packet sniffing.

## Troubleshooting

- Ensure all required Python libraries are installed.
- Make sure the custom modules are in the correct directory.
- Run the application with Python 3.11 or greater.
- For any issues, refer to the error messages displayed by `MessageBox`.
