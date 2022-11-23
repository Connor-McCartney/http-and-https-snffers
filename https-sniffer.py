from scapy.all import sniff, IP
from scapy.layers.http import HTTPRequest
from socket import gethostbyaddr, herror


duplicates = []

def https_sniff(packet):
    if packet.haslayer(HTTPRequest) or packet.haslayer(IP):
        dest_ip = packet[IP].dst 
        if dest_ip not in duplicates:
            try:
                host = gethostbyaddr(dest_ip)[0]
            except herror:
                host = ""
            duplicates.append(dest_ip)
            print(dest_ip + " "*(20-len(dest_ip)) + host)

            
def main():
    print("HTTPS sniffing started...")
    sniff(filter="port 443", prn=https_sniff)

    
if __name__ == "__main__":
    main()
