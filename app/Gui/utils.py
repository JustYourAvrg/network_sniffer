import customtkinter as ctk
import requests
import winsound

from psutil import net_if_addrs
from scapy.all import IP, raw, hexdump
from .messagebox import MessageBox


def get_interfaces():
    try:
        interfaces = net_if_addrs()
        interfaces = list(interfaces.keys())
    except AttributeError as e:
        return e

    return interfaces


def make_sniffer_frames(master, row, col, fg, label, display=False):
    frame = ctk.CTkFrame(master, fg_color=fg)
    frame.grid(row=row, column=col, padx=5, pady=5)
    frame.grid_propagate(0)

    label = ctk.CTkLabel(frame, text=label)
    label.grid(row=1, column=0, padx=(10, 0), pady=5, sticky='w')

    if display:
        display_area = ctk.CTkTextbox(frame, height=480, fg_color=fg, state='disabled')
        display_area.grid(row=2, column=0, padx=5, pady=(0, 0), sticky='nsew')

        return display_area
    
    return frame


def make_geolocation_labels(master, row, col, fg, label=""):
    label = ctk.CTkLabel(master, fg_color=fg, text=label, font=ctk.CTkFont(size=24, weight='bold'))
    label.grid(row=row, column=col, padx=15, pady=10, sticky='w')

    return label


def get_lookup_data(ip):
    request = requests.get(url=f'http://ipwhois.app/json/{ip}')
    request = request.json()

    raw_data = IP(dst=ip) / raw(b'\x00' * 100)

    try:
        if not request['success']:
            winsound.MessageBeep()
            MessageBox.showerror(title=f"ERROR Requesting data on IP {ip}", message=f"Invalid IP {ip}")
            return
    except Exception as e:
        pass

    return_data = {
        "ip_res": request['ip'],
        'type': request['type'],
        'region': request['region'],
        'city': request['city'],
        'isp': request['isp'],
        'asn': request['asn'],
        'org': request['org'],
        'raw_data': raw_data
    }

    return return_data

