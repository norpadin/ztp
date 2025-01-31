import socket
import struct
import time
import threading
from tftpy import TftpServer
import json


class DHCPServer:
    def __init__(
            self, iface="eth0", ip_range=("192.168.1.100", "192.168.1.200"),
            gateway="192.168.1.1", dns_domain="example.com",
            dns_server="8.8.8.8", bootfile="pxelinux.0",
            tftp_server="192.168.1.2", lease_file="leases.json"):
        self.iface = iface
        self.ip_range = ip_range
        self.gateway = gateway
        self.dns_domain = dns_domain
        self.dns_server = dns_server
        self.bootfile = bootfile
        self.tftp_server = tftp_server
        self.lease_file = lease_file
        self.leases = self.load_leases()
        self.sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        self.sock.bind(("", 67))

    def load_leases(self):
        try:
            with open(self.lease_file, "r") as f:
                return json.load(f)
        except FileNotFoundError:
            return {}

    def save_leases(self):
        with open(self.lease_file, "w") as f:
            json.dump(self.leases, f, indent=4)

    def get_next_ip(self):
        start_ip, end_ip = [
            struct.unpack('!I', socket.inet_aton(ip))[0]
            for ip in self.ip_range]
        for ip_int in range(start_ip, end_ip + 1):
            ip = socket.inet_ntoa(struct.pack('!I', ip_int))
            if ip not in self.leases.values():
                return ip
        return None

    def handle_dhcp(self):
        while True:
            data, addr = self.sock.recvfrom(1024)
            if data[0] == 1:  # DHCP Discover
                client_mac = ':'.join(f'{b:02x}' for b in data[28:34])
                offered_ip = self.get_next_ip()
                if not offered_ip:
                    continue
                self.leases[client_mac] = offered_ip
                self.save_leases()
                self.send_offer(addr, offered_ip, client_mac)

    def send_offer(self, addr, ip, mac):
        transaction_id = b'\x39\x03\xf3\x26'
        offer_packet = b'\x02' + transaction_id + b'\x00' * 32
        offer_packet += socket.inet_aton(ip)  # Your Offered IP
        offer_packet += socket.inet_aton(self.gateway)  # Gateway
        offer_packet += socket.inet_aton(self.dns_server)  # DNS Server
        # Bootfile Option
        offer_packet += struct.pack('!B',
                                    67) + self.bootfile.encode() + b'\x00'
        # TFTP Server Option
        offer_packet += struct.pack('!B',
                                    150) + self.tftp_server.encode() + b'\x00'
        self.sock.sendto(offer_packet, addr)

    def start(self):
        print("Starting DHCP Server...")
        threading.Thread(target=self.handle_dhcp, daemon=True).start()


class TFTPServerWrapper:
    def __init__(self, tftp_directory="tftpboot"):
        self.tftp_directory = tftp_directory
        self.server = TftpServer(self.tftp_directory)

    def start(self):
        print("Starting TFTP Server...")
        self.server.listen("0.0.0.0", 69)


if __name__ == "__main__":
    dhcp_server = DHCPServer()
    tftp_server = TFTPServerWrapper()

    threading.Thread(target=dhcp_server.start, daemon=True).start()
    tftp_server.start()
