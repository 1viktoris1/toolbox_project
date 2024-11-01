"""access to sublist3r functionality, terminal commands and send requests to http sites. """
import argparse
import sys
import sublist3r
import requests

# Global variables for settings
domain = None
ports = None
enable_bruteforce = False
engines = None
subdomains = []
verbose = False

def enumerate_subdomains(domain, ports, engines, enable_bruteforce, verbose):
    """Enumerate subdomane with sublist3r och inställningar för portar och motorer."""
    try:
        ports_str = ",".join(map(str, ports)) if ports else None
        engines_str = ",".join(engines) if engines else None

        if verbose:
            print(f"[+] Enumerating subdomains for {domain} with settings: Ports={ports_str}, Engines={engines_str}, Bruteforce={enable_bruteforce}")
        subdomains = sublist3r.main(
            domain=domain,
            ports=ports_str,
            engines=engines_str,
            threads=10,
            savefile=None,
            enable_bruteforce=enable_bruteforce,
            silent=not verbose,
            verbose=verbose
        )
        return subdomains
    except Exception as e:
        if verbose:
            print(f"[-] Error during subdomain enumeration: {e}")
        return []

def check_subdomain_availability(subdomain, verbose):
    """Checks if subdomain is active through http and https"""
    urls = [f"http://{subdomain}", f"https://{subdomain}"]
    for url in urls:
        try:
            response = requests.get(url, timeout=5)
            if response.status_code == 200:
                if verbose:
                    print(f"[+] {subdomain} is active on {url}")
                return True
        except requests.RequestException:
            if verbose:
                print(f"[-] Failed to reach {url}")
            continue
    return False

def save_results(subdomains, filename, verbose):
    """Saves result to file"""
    try:
        with open(filename, "w") as f:
            for subdomain in subdomains:
                f.write(f"{subdomain}\n")
        if verbose:
            print(f"[+] Results saved to {filename}")
    except IOError as e:
        if verbose:
            print(f"[-] Error saving results to file: {e}")

def load_subdomains_from_file(filename):
    """loads subdomains from file"""
    try:
        with open(filename, "r") as f:
            loaded_subdomains = [line.strip() for line in f if line.strip()]
        print(f"[+] Loaded {len(loaded_subdomains)} subdomains from {filename}")
        return loaded_subdomains
    except IOError as e:
        print(f"[-] Error reading file {filename}: {e}")
        return []

def show_settings():
    """Shows current settings"""
    print("\n=== Current Settings ===")
    print(f"Domain: {domain or 'Not Set'}")
    print(f"Ports: {ports or 'Default'}")
    print(f"Brute Force: {'Enabled' if enable_bruteforce else 'Disabled'}")
    print(f"Engines: {engines or 'Default'}")
    print(f"Verbose: {'Enabled' if verbose else 'Disabled'}")

def configure_settings():
    """Set flags through meny"""
    global domain, ports, enable_bruteforce, engines, verbose

    domain = input("Enter the domain to enumerate subdomains for (leave blank to keep current): ") or domain
    ports_input = input("Enter ports to scan (comma-separated, e.g., '80,443') or leave blank for default: ")
    ports = [int(p.strip()) for p in ports_input.split(",") if p.strip()] if ports_input else ports
    enable_bruteforce_input = input("Enable brute force? (yes/no) or leave blank for current setting: ").strip().lower()
    enable_bruteforce = enable_bruteforce if not enable_bruteforce_input else (enable_bruteforce_input == 'yes')
    engines_input = input("Enter search engines to use (comma-separated, e.g., 'google,bing') or leave blank for default: ")
    engines = [e.strip().lower() for e in engines_input.split(",") if e.strip()] if engines_input else engines
    verbose_input = input("Enable verbose mode? (yes/no) or leave blank for current setting: ").strip().lower()
    verbose = verbose if not verbose_input else (verbose_input == 'yes')

def interactive_menu():
    """Interactive meny."""
    global subdomains
    while True:
        print("\n=== Subdomain Enumeration Tool ===")
        print("1. Set Domain and Options")
        print("2. Show Current Settings")
        print("3. Enumerate Subdomains")
        print("4. Check Subdomain Availability")
        print("5. Save Results to File")
        print("6. Load Subdomains from File")
        print("7. Exit")    
        choice = input("Choose an option (1-6): ")
        if choice == "1":
            configure_settings()
        elif choice == "2":
            show_settings()
        elif choice == "3":
            if not domain:
                print("[-] Domain not set. Please set domain and options first.")
                continue
            subdomains = enumerate_subdomains(domain, ports, engines, enable_bruteforce, verbose)
            if verbose:
                print(f"[+] Found {len(subdomains)} subdomains.")
        elif choice == "4":
            if not subdomains:
                print("[-] Please enumerate subdomains first.")
                continue
            active_subdomains = []
            for subdomain in subdomains:
                if check_subdomain_availability(subdomain, verbose):
                    active_subdomains.append(subdomain)
                elif verbose:
                    print(f"[-] {subdomain} is not active.")
            subdomains = active_subdomains
        elif choice == "5":
            if not subdomains:
                print("[-] No subdomains to save. Please enumerate first.")
                continue
            filename = input("Enter filename to save results: ")
            save_results(subdomains, filename, verbose)
        elif choice == "6":
            filename = input("Enter filename to load subdomains from: ")
            subdomains = load_subdomains_from_file(filename)
        elif choice == "7":
            print("[+] Exiting.")
            sys.exit()
        else:
            print("[-] Invalid choice. Please choose a valid option.")

def main():
    """Main function"""
    parser = argparse.ArgumentParser(description="Subdomain Enumeration Tool")
    parser.add_argument("domain", nargs="?", help="Domain to enumerate subdomains for")
    parser.add_argument("-f", "--file", help="File to save the results", default=None)
    parser.add_argument("--ports", help="Comma-separated list of ports to scan, e.g., '80,443'")
    parser.add_argument("--bruteforce", action="store_true", help="Enable brute force enumeration")
    parser.add_argument("--engines", help="Comma-separated list of search engines to use, e.g., 'google,bing'")
    parser.add_argument("-v", "--verbose", action="store_true", help="Enable verbose mode for additional details")
    parser.add_argument("--load", help="Load subdomains from a file instead of enumerating", default=None)

    args = parser.parse_args()
    if args.domain is None and args.file is None and args.ports is None and args.engines is None and not args.bruteforce and not args.verbose:
        interactive_menu() # if no arguments, run meny
        return   
    global domain, ports, enable_bruteforce, engines, verbose
    domain = args.domain
    ports = [int(p.strip()) for p in args.ports.split(",")] if args.ports else None
    engines = [e.strip().lower() for e in args.engines.split(",")] if args.engines else None
    enable_bruteforce = args.bruteforce
    verbose = args.verbose
    if args.load:
        subdomains = load_subdomains_from_file(args.load)
    else:   
        if verbose:
            print(f"[+] Starting enumeration for {domain}")
        subdomains = enumerate_subdomains(domain, ports, engines, enable_bruteforce, verbose)
    active_subdomains = []
    for subdomain in subdomains:
        if check_subdomain_availability(subdomain, verbose):
            active_subdomains.append(subdomain)
        elif verbose:
            print(f"[-] {subdomain} is not active.")
    if args.file:
        save_results(active_subdomains, args.file, verbose)

if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        print("\n[-] Process interrupted by user.")
    except Exception as e:
        print(f"[-] Unexpected error: {e}")
