import time

from scapy.all import sniff


class SnifferClass:
    def __init__(self):
        self.packets = [] # List to store sniffed packets
        self.error = False # Error variable

    def sniffer(self, iface=None):
        try:
            sniffed_packet = sniff(iface=iface, count=1, filter="", timeout=3)

            src = sniffed_packet[0][1].src # packet source IP
            dst = sniffed_packet[0][1].dst # packet destination IP
            sport = sniffed_packet[0][1].sport # packet source port
            proto = "TCP" if sniffed_packet[0][1].proto == 6 else "UDP" if sniffed_packet[0][1].proto == 17 else "OTHER" # TCP, UDP, or OTHER depending on the proto
            timestamp = time.time() # Timestamp of then the packet was sniffed

            # Append the packet data to the packets list
            self.packets.append((src, dst, sport, proto, timestamp))
            
            # Set self.error to true if no packets are added
            if len(self.packets) == 0:
                self.error = True

        except AttributeError:
            pass

    
    def check_if_active(self):
        cur_time = time.time() # Get the current time
        
        # Filter the packets on if their active or not, while removing duplicates
        filtered_packets = [pkt[:4] for pkt in self.packets if cur_time - pkt[4] <= 3]
        filtered_packets = list(set(filtered_packets))
        return filtered_packets