"""Function for termianl commands and sniff/dns magic stuff"""
import argparse
from scapy.all import sniff, send, IP, TCP, UDP, ICMP, DNSQR, DNS
from dnslib import DNSRecord

def manipulate_packet(packet, args):
    """Manipulate and display packet based on user-defined protocol filters."""
    output = ""
    if packet.haslayer(IP):
        if args.tcp and packet.haslayer(TCP):
            if packet[TCP].dport == args.port or packet[TCP].sport == args.port:
                output = f"Captured a TCP packet: {packet.summary()}\n"
                modified_packet = packet.copy()
                modified_packet[TCP].flags = "PA"  # Modify TCP flags
                modified_packet[TCP].seq += 100    # Adjust sequence number
                send(modified_packet)

        elif args.udp and packet.haslayer(UDP):
            if packet[UDP].dport == args.port or packet[UDP].sport == args.port:
                output = f"Captured a UDP packet: {packet.summary()}\n"
                modified_packet = packet.copy()
                if modified_packet.haslayer(DNSQR):
                    modified_packet[DNS].id = 0xAAAA  # Modify DNS id
                    modified_packet[DNS].qd.qname = b"manipulated.com."
                send(modified_packet)

        elif args.icmp and packet.haslayer(ICMP):
            output = f"Captured an ICMP packet: {packet.summary()}\n"
            modified_packet = packet.copy()
            modified_packet[ICMP].type = 0  # Change to Echo Reply
            send(modified_packet)

    if output and args.output:
        save_output(output, args.output)

def save_output(output, filename):
    """Save captured packet details to a file."""
    with open(filename, 'a') as file:
        file.write(output)

def sniff_packets(args):
    """Capture and manipulate packets based on specified interface and protocol."""
    def packet_callback(packet):
        manipulate_packet(packet, args)

    sniff(iface=args.interface, prn=packet_callback, count=args.count)

def dns_tunnel(args):
    """Create a DNS tunnel by sending DNS queries to the specified server."""
    print(f"Starting DNS tunnel to server: {args.server}")
    while True:
        query = DNSRecord.question(args.domain)
        response = query.send(args.server, 53, tcp=False)
        response_record = DNSRecord.parse(response)
        result = f"Received DNS response: {response_record}\n"
        print(result)
        if args.output:
            save_output(result, args.output)

def display_menu():
    """Display the main menu and handle user inputs for program execution."""
    print("\nNetwork Packet Analyzer and DNS Tunnel")
    print("=====================================")
    print("1. Sniff and manipulate packets")
    print("2. Create a DNS tunnel")
    print("3. Exit")

    choice = input("\nChoose an option (1-3): ")
    if choice == '1':
        interface = input("Enter the network interface (e.g., Wi-Fi): ")
        protocol = input("Filter by protocol (tcp, udp, icmp): ").lower()
        port = int(input("Enter the port number (default is 80): ") or 80)
        count = int(input("Enter the number of packets to capture (default is 10): ") or 10)
        output_file = input("Enter output file to save results (optional): ")

        args = argparse.Namespace(interface=interface, tcp=protocol == 'tcp',
                                  udp=protocol == 'udp', icmp=protocol == 'icmp',
                                  port=port, count=count, output=output_file)
        sniff_packets(args)

    elif choice == '2':
        server = input("Enter the DNS server (e.g., 8.8.8.8): ")
        domain = input("Enter the domain to use for DNS queries: ")
        output_file = input("Enter output file to save results (optional): ")

        args = argparse.Namespace(server=server, domain=domain, output=output_file)
        dns_tunnel(args)

    elif choice == '3':
        print("Exiting...")
        exit()
    else:
        print("Invalid choice, please try again.")

def main():
    """Main function to run the program with a menu."""
    while True:
        display_menu()

if __name__ == "__main__":
    main()
