#skrivet i windows 11, visual studio code.
#Viktor Jönsson, Arbetat själv.

import nmap
import os
import subprocess
import argparse

def scan_ip(ip_address, flags):
    nm = nmap.PortScanner()
    try:
        print(f"Scanning {ip_address} with flags: {flags}")
        nm.scan(ip_address, arguments=flags)
        if ip_address in nm.all_hosts():
            return nm[ip_address]
        else:
            print(f"error: Scanning {ip_address} failed or no host found.")
            return None
    except nmap.PortScannerError as e:
        print(f"Nmap-error: {e}")
    except Exception as e:
        print(f"Something went wrong: {e}")
    return None

def save_scan_results(results, filename):
    try:
        with open(filename, 'w') as file:
            for host, result in results.items():
                file.write(f"Resluts for {host}:\n")
                file.write("------------------------------------------------\n")
                for proto in result.all_protocols():
                    ports = result[proto].keys()
                    for port in ports:
                        state = result[proto][port]['state']
                        name = result[proto][port].get('name', 'unknown')
                        product = result[proto][port].get('product', 'unknown')
                        version = result[proto][port].get('version', 'unknown')
                        file.write(f"Port: {port}, State: {state}, Service: {name}, Product: {product}, Version: {version}\n")
                file.write("\n")
        print(f"Result saved to {filename}.")
    except Exception as e:
        print(f"Could not save file: {e}")

def read_ips_from_file(filename):
    if not os.path.exists(filename):
        print(f"File {filename} not found.")
        return []

    try:
        with open(filename, 'r') as file:
            ip_addresses = file.readlines()
        return [ip.strip() for ip in ip_addresses if ip.strip()]
    except Exception as e:
        print(f"Something went wrong when reading file : {e}")
        return []

def show_nmap_flags():
    try:
        result = subprocess.run(['nmap', '--help'], capture_output=True, text=True)
        if result.returncode == 0:
            print("available flags:\n")
            print(result.stdout)
        else:
            print("Could not get flags, showing preselected alternative instead")
            show_default_nmap_flags()
    except FileNotFoundError:
        print("Nmap may not be installed or could not be found in PATH.")
        show_default_nmap_flags()

def show_default_nmap_flags():  
    print("""
Popular Nmap-flaggs:
  -sS    SYN-scan
  -sV    Versiondetection for services
  -sP    Ping-scan for active hosts
  -O     Operatingsystem detection
  -A     Aggressive scan (OS + versions + traceroute)
  -p <ports>    choose ports to scan (example., -p 1-1000)
  -T4    Faster scans (T0 to T5,)
  --script <scriptnamn>  add scripts
    """)

def menu():
    results = {}
    scan_flags = "-sV" 
    while True:
        print("\n--- Nmap IP-scanner ---")
        print("1. Choose flags (currently: {0})".format(scan_flags))
        print("2. Scan a ip-adress")
        print("3. Scan from file")
        print("4. Show previous scans")
        print("5. Save results to file")
        print("6. Show list of nmap-flags")
        print("7. Quit")

        choice = input("What to do?: ")

        if choice == '1':
            scan_flags = input("choose flags (example., -sV, -O, -p 1-100): ").strip()
            if not scan_flags:
                print("no flags selected, returns to standard: -sV")
                scan_flags = "-sV"

        elif choice == '2':
            ip = input("Choose ip to scan: ").strip()
            if ip:
                scan_result = scan_ip(ip, scan_flags)
                if scan_result:
                    results[ip] = scan_result

        elif choice == '3':
            filename = input("which file to read from?: ").strip()
            ips = read_ips_from_file(filename)
            if ips:
                for ip in ips:
                    scan_result = scan_ip(ip, scan_flags)
                    if scan_result:
                        results[ip] = scan_result

        elif choice == '4':
            if results:
                for host, result in results.items():
                    print(f"\nResults for {host}:")
                    for proto in result.all_protocols():
                        ports = result[proto].keys()
                        for port in ports:
                            state = result[proto][port]['state']
                            print(f"Port: {port}, State: {state}")
            else:
                print("Nothing to show.")

        elif choice == '5':
            if results:
                filename = input("Choose name for file: ").strip()
                if filename:
                    save_scan_results(results, filename)
            else:
                print("Nothing to save.")

        elif choice == '6':
            show_nmap_flags()

        elif choice == '7':
            print("Quiting.")
            break

        else:
            print("not a valid selection try again.")
def main():
    parser = argparse.ArgumentParser(description="Nmap IP-scanner")
    parser.add_argument("--ip", type=str, help="Choose a ip-adress to scan")
    parser.add_argument("--file", type=str, help="Choose a file to scan ip-adresses from")
    parser.add_argument("--flags", type=str, default="-sV", help="select nmap-flaggs to use when scanning")
    parser.add_argument("--save", type=str, help="save to file of choice")

    args = parser.parse_args()

    results = {}
    if args.ip:
        result = scan_ip(args.ip, args.flags)
        if result:
            results[args.ip] = result
    elif args.file:
        ips = read_ips_from_file(args.file)
        for ip in ips:
            result = scan_ip(ip, args.flags)
            if result:
                results[ip] = result

    if results and args.save:
        save_scan_results(results, args.save)
    elif not args.ip and not args.file:
        menu()

if __name__ == '__main__':
    main()
