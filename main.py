from app.setup import Setup
Setup.import_required_modules()

import customtkinter as ctk
import threading
import winsound
import time
import sys
import matplotlib.pyplot as plt

from matplotlib.backends.backend_tkagg import FigureCanvasTkAgg
from scapy.all import hexdump
from app.sniffer import SnifferClass
from app.Gui.messagebox import MessageBox
from app.Gui.utils import get_interfaces, make_sniffer_frames, make_geolocation_labels, get_lookup_data


class GuiFramesAndUtility:
    def __init__(self, iface, proto_filter, sniffing, frame):
        # Sniffing variables
        self.iface = iface
        self.proto_filter = proto_filter
        self.sniffing = sniffing

        # Frame variables
        self.cur_frame = frame

        # data Variables
        self.most_sniffed_src_ip = 0
        self.most_sniffed_dst_ip = 0
        self.sniffed_udp = 0
        self.sniffed_tcp = 0
        self.sniffed_other = 0

    # Function to set the interface to sniff on
    def set_iface(self, iface):
        if not self.sniffing:
            self.iface = iface
            print(iface)
        elif self.sniffing:
            winsound.MessageBeep()
            MessageBox.showerror(title='ERROR', message="Can't change interface while sniffing")
            iface_selector.configure(value=self.iface)

    
    # Function to set the protocol filter
    def set_proto(self, proto):
        self.proto_filter = proto
        print(proto)
        

    # Frame swap function
    def frame_swap(self, frame, frame_btn, all_buttons):
        # Configure all buttons to normal
        for btn in all_buttons:
            btn.configure(state='normal')
        # Configure the selected button to disabled
        frame_btn.configure(state='disabled')

        if hasattr(self, 'data_thread'):
            self.data_updating_loop = False
            self.data_thread.join(0.3)
            self.data_frame.grid_remove()
            print("ended data thread")

        # Remove the grid for Sniffer, Lookup, and data frame
        try:
            self.sniffer_frame.grid_remove()
            self.lookup_frame.grid_remove()
            self.data_frame.grid_remove()

        except AttributeError:
            pass
        
        # Grid the chosen frame
        if frame == 'Sniffer':
            try:
                self.sniffer_frame.grid()
            except Exception:
                self.sniffer_frame_func()
        elif frame == 'Lookup':
            try:
                self.lookup_frame.grid()
            except Exception:
                self.lookup_frame_func()
        elif frame == 'Data':
            try:
                self.data_frame.grid()
                self.start_data_thread()
            except Exception:
                self.data_frame_func()
                self.start_data_thread()


        self.cur_frame = frame
    
    # Sniffer Frame
    def sniffer_frame_func(self):
        # Make the frame for the sniffer page
        self.sniffer_frame = ctk.CTkFrame(root, width=1060, height=540, fg_color='#232323')
        self.sniffer_frame.grid(row=1, column=0, sticky="")
        self.sniffer_frame.grid_propagate(0)

        # Configure the grid_column
        self.sniffer_frame.grid_columnconfigure([0, 1, 2, 3], weight=1)

        # Frame for each data from the packet to display (Source IP | Destination IP | Source Port | Protocol)
        self.ip_frame = make_sniffer_frames(self.sniffer_frame, 0, 0, '#232323', "IP") # Returns a frame, and label
        self.dst_frame = make_sniffer_frames(self.sniffer_frame, 0, 1, '#232323', "DST") # Returns a frame, and label
        self.sport_frame = make_sniffer_frames(self.sniffer_frame, 0, 2, '#232323', "SPORT", display=True) # Returns a frame, label, and display
        self.proto_frame = make_sniffer_frames(self.sniffer_frame, 0, 3, '#232323', "PROTO", display=True) # Returns a frame, label, and display

    
    # Lookup Frame
    def lookup_frame_func(self):
        # Make the lookup frame
        self.lookup_frame = ctk.CTkFrame(root, width=1060, height=540, fg_color="#232323")
        self.lookup_frame.grid(row=1, column=0, rowspan=2, sticky="")
        self.lookup_frame.grid_propagate(0)

        # Configure the lookup frame
        self.lookup_frame.grid_rowconfigure(0, weight=1)
        self.lookup_frame.grid_columnconfigure(0, weight=1)

        # Frame for displaying Geolocation data
        self.geolocation_frame = ctk.CTkFrame(self.lookup_frame, fg_color="#323232", width=500, corner_radius=10, border_width=2, border_color="#1e1e1e")
        self.geolocation_frame.grid(row=0, column=0, padx=10, pady=10, sticky='ns')
        self.geolocation_frame.grid_propagate(0)

        self.geolocation_frame.grid_rowconfigure([0, 1, 2, 3, 4, 5, 6], weight=1)

        # Labels and displays for ( IP | TYPE | REGION | CITY | ISP | ASN | ORG )
        self.ip_label = make_geolocation_labels(self.geolocation_frame, 0, 0, "#323232", "IP >>>")
        self.ip_display = make_geolocation_labels(self.geolocation_frame, 0, 1, "#323232")

        self.type_label = make_geolocation_labels(self.geolocation_frame, 1, 0, "#323232", "TYPE >>>")
        self.type_display = make_geolocation_labels(self.geolocation_frame, 1, 1, "#323232")

        self.region_label = make_geolocation_labels(self.geolocation_frame, 2, 0, "#323232", "REGION >>>")
        self.region_display = make_geolocation_labels(self.geolocation_frame, 2, 1, "#323232")

        self.city_label = make_geolocation_labels(self.geolocation_frame, 3, 0, "#323232", "CITY >>>")
        self.city_display = make_geolocation_labels(self.geolocation_frame, 3, 1, "#323232")

        self.isp_label = make_geolocation_labels(self.geolocation_frame, 4, 0, "#323232", "ISP >>>")
        self.isp_display = make_geolocation_labels(self.geolocation_frame, 4, 1, "#323232")

        self.asn_label = make_geolocation_labels(self.geolocation_frame, 5, 0, "#323232", "ASN >>>")
        self.asn_display = make_geolocation_labels(self.geolocation_frame, 5, 1, "#323232")

        self.org_label = make_geolocation_labels(self.geolocation_frame, 6, 0, "#323232", "ORG >>>")
        self.org_display = make_geolocation_labels(self.geolocation_frame, 6, 1, "#323232")

        # Frame for displaying raw_data
        self.raw_data_frame = ctk.CTkFrame(self.lookup_frame, fg_color="#323232", width=460, corner_radius=10, border_width=2, border_color="#1e1e1e")
        self.raw_data_frame.grid(row=1, column=0, padx=10, pady=10, sticky='ns')
        self.raw_data_frame.grid_propagate(0)

        self.raw_data_frame.columnconfigure(0, weight=1)
        self.raw_data_frame.rowconfigure(0, weight=1)

        self.raw_data_display = ctk.CTkTextbox(self.raw_data_frame, fg_color="#1e1e1e", state='disabled')
        self.raw_data_display.grid(row=0, column=0, padx=5, pady=5, sticky='nsew')


    # Function for when user clicks on a SRC or DST button on the sniffer page
    def ip_lookup_command(self, ip):
        data = get_lookup_data(ip=ip)

        self.sniffer_frame.grid_remove()
        self.cur_frame = 'Lookup'

        all_buttons[0].configure(state='normal')
        all_buttons[1].configure(state='disabled')

        self.lookup_frame_func()

        self.ip_display.configure(text=data['ip_res'])
        self.type_display.configure(text=data['type'])
        self.region_display.configure(text=data['region'])
        self.city_display.configure(text=data['city'])
        self.isp_display.configure(text=data['isp'])
        self.asn_display.configure(text=data['asn'])
        self.org_display.configure(text=data['org'])

        self.raw_data_display.configure(state='normal')
        self.raw_data_display.insert(ctk.END, text=hexdump(data['raw_data'], dump=True))
        self.raw_data_display.configure(state='disabled')

    
    # data Frame
    def data_frame_func(self):
        self.data_frame = ctk.CTkFrame(root, width=1060, height=540, fg_color="#232323")
        self.data_frame.grid(row=1, column=0, columnspan=2, sticky="")
        self.data_frame.grid_propagate(0)

        self.data_frame.grid_rowconfigure(0, weight=1)
        self.data_frame.grid_columnconfigure([0, 1], weight=1)

        self.protocol_pie_chart = ctk.CTkFrame(self.data_frame, fg_color="#323232", width=400, height=400, corner_radius=10)
        self.protocol_pie_chart.grid(row=0, column=0)
        self.protocol_pie_chart.grid_rowconfigure(0, weight=1)
        self.protocol_pie_chart.grid_columnconfigure(0, weight=1)
        self.protocol_pie_chart.grid_propagate(0)

        self.most_sniffed_ips = ctk.CTkFrame(self.data_frame, fg_color='#323232', width=500, corner_radius=10)
        self.most_sniffed_ips.grid(row=0, column=1, padx=10, pady=10)
        self.most_sniffed_ips.grid_propagate(0)

        self.most_sniffed_ips.grid_rowconfigure([0, 1], weight=1)
        self.most_sniffed_ips.grid_columnconfigure(0, weight=1)

        self.most_sniffed_src_label = ctk.CTkLabel(self.most_sniffed_ips, text=f"Most Sniffed SRC IP >>> {self.most_sniffed_src_ip}", font=ctk.CTkFont(family='Terminal', size=16))
        self.most_sniffed_src_label.grid(row=0, column=0, padx=(15, 5), pady=5, sticky='w')

        self.most_sniffed_dst_label = ctk.CTkLabel(self.most_sniffed_ips, text=f"Most Sniffed DST IP >>> {self.most_sniffed_dst_ip}", font=ctk.CTkFont(family='Terminal', size=16))
        self.most_sniffed_dst_label.grid(row=1, column=0, padx=(15, 5), pady=5, sticky='w')

    # Creates the graph for the sniffed protocols
    def create_graph(self):
        fig = plt.Figure(facecolor="#1e1e1e")
        ax = fig.add_subplot()

        data = [self.sniffed_tcp, self.sniffed_udp, self.sniffed_other]
        labels = ['TCP', 'UDP', 'OTHER']

        data = [self.sniffed_tcp, self.sniffed_udp, self.sniffed_other]
        valid_labels = [label for label, value in zip(labels, data) if value > 0]
        valid_data = [value for value in data if value > 0]

        ax.pie(x=valid_data, labels=valid_labels, autopct=lambda pct: f'{int(pct * sum(valid_data) / 100)}', colors=['#333333', '#444444', '#555555'])

        canvas = FigureCanvasTkAgg(fig, master=self.protocol_pie_chart)
        canvas.draw()
        canvas.get_tk_widget().grid(row=0, column=0)

        return canvas


    def update_data(self):
        while self.data_updating_loop:
            self.protocol_pie_chart.grid_remove()
            self.protocol_pie_chart.grid()
            self.create_graph()
            
            self.most_sniffed_src_label.configure(text=f"Most Sniffed SRC IP >>> {self.most_sniffed_src_ip}")
            self.most_sniffed_dst_label.configure(text=f"Most Sniffed DST IP >>> {self.most_sniffed_dst_ip}")
            time.sleep(0.5)


    def start_data_thread(self):
        self.data_updating_loop = True
        self.data_thread = threading.Thread(target=self.update_data)
        self.data_thread.start()
    
    
    # Sniffing thread function
    def start_sniffing_thread(self):
        try:
            # Change the text of the start button and the command
            start_stop_button.configure(text='Stop Sniffing', command=FramesAndUtility.stop_sniffing)
            
            # Set sniffing to True, and start the thread for the start_sniffing function
            self.sniffing = True
            self.sniffer_thread = threading.Thread(target=self.start_sniffing)
            self.sniffer_thread.start()
        except Exception as e:
            print(e)

    
    # Sniffing function
    def start_sniffing(self):
        self.src_buttons = [] # List to store displayed source IP Buttons
        self.dst_buttons = [] # List to store displayed destination IP Buttons

        self.sniffed_src_dict = {}
        self.sniffed_dst_dict = {}

        try:
            # While sniffing is True start sniffing, then check for active packets, then update the display with the active packets
            while self.sniffing:
                Sniffer.sniffer(iface=self.iface)

                # If and error is raised in the sniffer, play a sound, show the error, and stop the sniffing thread
                if Sniffer.error:
                    winsound.MessageBeep()
                    MessageBox.showerror("ERROR", message=f"Error sniffing packets on interface {self.iface}")
                    self.stop_sniffing()

                active_packets = Sniffer.check_if_active()

                self.update_sniffer_displays(active_packets)
                time.sleep(0.5)
        except Exception as e:
            print(e)


    def update_sniffer_displays(self, packets):
        try:
            # Combine the src and dst button lists and destroy all buttons
            for btn in self.src_buttons + self.dst_buttons:
                btn.destroy()

            # Clear the src and dst buttons list
            self.src_buttons.clear()
            self.dst_buttons.clear()

            # Configure the sport and proto displays to 'normal'
            self.sport_frame.configure(state='normal')
            self.proto_frame.configure(state='normal')

            # Delete all text from the first line to the end line of the display for sport and proto
            self.sport_frame.delete(0.0, ctk.END)
            self.proto_frame.delete(0.0, ctk.END)

            # Iterate through the packets list, start the iterator at 2 instead of 0
            for i, packet in enumerate(packets, start=2):
                # Get the src, dst, sport, and proto from the packet
                src, dst, sport, proto = packet
                if proto == 'TCP':
                    self.sniffed_tcp += 1
                elif proto == 'UDP':
                    self.sniffed_udp += 1
                elif proto == 'OTHER':
                    self.sniffed_other += 1
                
                self.sniffed_src_dict[src] = self.sniffed_src_dict.get(src, 0) + 1
                self.sniffed_dst_dict[dst] = self.sniffed_dst_dict.get(dst, 0) + 1

                # Check for the protocol filter and display according to the filter
                if self.proto_filter == "None" or (self.proto_filter == "UDP" and proto == "UDP") or (self.proto_filter == "TCP" and proto == "TCP"):
                    # Create a button for the source IP then append the button to the source buttons list
                    src_button = ctk.CTkButton(master=self.ip_frame, text=src, width=120, height=5, fg_color="#232323", hover_color="#2e2e2e", command=lambda ip=src: self.ip_lookup_command(ip))
                    src_button.grid(row=i, column=0)
                    self.src_buttons.append(src_button)
                    # Create a button for the destination IP then append the button to the destination buttons list
                    dst_button = ctk.CTkButton(master=self.dst_frame, text=dst, width=120, height=5, fg_color="#232323", hover_color="#2e2e2e", command=lambda ip=dst: self.ip_lookup_command(ip))
                    dst_button.grid(row=i, column=0)
                    self.dst_buttons.append(dst_button)

                    # Insert the source port and protocol into their displays starting from the last line
                    self.sport_frame.insert(ctk.END, f"{sport}\n")
                    self.proto_frame.insert(ctk.END, f"{proto}\n")
                
            # Disable the source port and protocol display
            self.sport_frame.configure(state='disabled')
            self.proto_frame.configure(state='disabled')
            
            self.most_sniffed_src_ip = max(self.sniffed_src_dict, key=self.sniffed_src_dict.get)
            self.most_sniffed_dst_ip = max(self.sniffed_dst_dict, key=self.sniffed_dst_dict.get)

        except Exception as e:
            print(e)

    
    # Stop sniffing function
    def stop_sniffing(self):
        try:
            # Set sniffing to False
            self.sniffing = False

            # If "sniffer_thread" has an attribute, configure the start/stop sniffing button text, and command
            if hasattr(self, 'sniffer_thread'):
                start_stop_button.configure(text='Start Sniffing', command=FramesAndUtility.start_sniffing_thread)
                # Stop the sniffer thread
                self.sniffer_thread.join(0.3)

        except Exception as e:
            print(e)


if __name__ == "__main__":
    try:
        # Set Variables
        FramesAndUtility = GuiFramesAndUtility(iface=get_interfaces()[0], proto_filter="None", sniffing=False, frame="Sniffer")
        Sniffer = SnifferClass()

        # Create root frame
        root = ctk.CTk()

        # Configure root frame
        root.title('Packet Sniffer')
        root.iconbitmap('icon.ico')
        root.geometry('1080x600')
        root.configure(fg_color='#1e1e1e')
        root.resizable(0, 0)
        root.grid_propagate(0)
        root.grid_rowconfigure(1, weight=1)

        # Create topbar
        # Topbar frame
        topbar = ctk.CTkFrame(root, fg_color='#232323', width=1080, height=40, corner_radius=0)
        topbar.grid(row=0, column=0)
        topbar.grid_propagate(0)

        # Interface Selector
        iface_selector = ctk.CTkOptionMenu(topbar, values=[iface for iface in get_interfaces()], width=240, 
                                            fg_color="#1e1e1e", 
                                            dropdown_text_color="#FFFFFF", 
                                            dropdown_fg_color="#1e1e1e",
                                            dropdown_hover_color="#3e3e3e",
                                            button_color="#4e4e4e",
                                            button_hover_color="#2e2e2e",
                                            command=FramesAndUtility.set_iface)
        iface_selector.grid(row=0, column=0, padx=5, pady=5)
        
        # Protocol filter selector
        protocol_filter_selector = ctk.CTkOptionMenu(topbar, values=['None', 'TCP', 'UDP'], width=50,
                                        fg_color="#1e1e1e",
                                        dropdown_text_color="#FFFFFF", 
                                        dropdown_fg_color="#1e1e1e",
                                        dropdown_hover_color="#3e3e3e",
                                        button_color="#4e4e4e",
                                        button_hover_color="#2e2e2e",
                                        command=FramesAndUtility.set_proto)
        protocol_filter_selector.grid(row=0, column=1, padx=(5, 160), pady=5)
        protocol_filter_selector.grid_propagate(0)

        # Frame Swap Buttons
        tabs = ["Sniffer", "Lookup", "Data"] # List for keeping all tabs
        all_buttons = [] # List for keeping all frame swapping buttons created
        for i, tab in enumerate(tabs, start=2):
            # Create the button(s)
            frame_button = ctk.CTkButton(topbar, text=tab,
                                        fg_color="#323232",
                                        hover_color="#1d1d1d",
                                        width=100)
            frame_button.grid(row=0, column=i, padx=5, pady=5)
            all_buttons.append(frame_button) # Append the button to the all_buttons list

            # Configure the frame button to add the command with the needed parameters
            frame_button.configure(command=lambda tab=tab, tab_btn=frame_button: FramesAndUtility.frame_swap(frame=tab, frame_btn=tab_btn, all_buttons=all_buttons))
        all_buttons[0].configure(state='disabled') # Set the first element (Sniffer) to disabled (Because Sniffer is the default)

        # Start/Stop button
        start_stop_button = ctk.CTkButton(topbar, text="Start Sniffing", fg_color="#323232", hover_color="#1d1d1d", width=100, command=FramesAndUtility.start_sniffing_thread)
        start_stop_button.grid(row=0, column=5, padx=(160, 5), pady=5)
        
        # Display the sniffer frame
        FramesAndUtility.sniffer_frame_func()

        # Run the GUI
        root.mainloop()
    except Exception as e:
        winsound.MessageBeep()
        MessageBox.showerror(title='ERROR', message=e)
        sys.exit(1)
