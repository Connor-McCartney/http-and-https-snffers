from scapy.all import sniff
from scapy.layers.http import HTTPRequest, Raw

def http_sniff(packet):
    if packet.haslayer(HTTPRequest):
        url = packet[HTTPRequest].Host.decode() + packet[HTTPRequest].Path.decode()
        print(url)
        if packet.haslayer(Raw):
            data = packet[Raw]
            print(data)

def main():
    print("HTTP sniffing started...")
    sniff(filter="port 80", prn=http_sniff)

if __name__ == "__main__":
    main()
