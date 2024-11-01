"""Modules adds functions for terminal commands and generate pseudo-random numbers"""
import argparse
import sys
import random

def encrypt_shellcode(shellcode, key):
    """Encrypt shellcode with XOR"""
    return bytes([shellcode[i] ^ key[i] for i in range(len(shellcode))])

def to_char_array(data):
    """Convert byte-array to C-format"""
    return ', '.join(f'0x{b:02x}' for b in data)

def load_shellcode_from_file(filename):
    """Load shellcode from file"""
    try:
        with open(filename, "rb") as file:
            return file.read()
    except FileNotFoundError:
        print(f"Error: Shellcode file '{filename}' not found.")
        return None
    
def generate_c_code(shellcode, key):
    """Generate and print C code"""
    encrypted_shellcode = encrypt_shellcode(shellcode, key)
    print("\nC code output:")
    print("unsigned char key[] = {" + to_char_array(key) + "};")
    print("unsigned char encrypted_shellcode[] = {" + to_char_array(encrypted_shellcode) + "};")

def main_menu():
    """main menu"""
    while True:
        print("\nShellcode Encryptor Menu:")
        print("1. Encrypt shellcode with random key")
        print("2. Load shellcode from file")
        print("3. Explain script functionality")
        print("4. Exit")
        choice = input("Choose an option (1-4): ")
        if choice == '1':
            shellcode_hex = input("Enter shellcode in hex format (e.g., \\x31\\xc0\\x50): ")
            shellcode = bytes.fromhex(shellcode_hex.replace("\\x", ""))
            key = bytes([random.randint(0, 255) for _ in range(len(shellcode))])
            generate_c_code(shellcode, key)
        elif choice == "2":
            filename = input("Enter the shellcode file path: ")
            shellcode = load_shellcode_from_file(filename)
            if shellcode is not None:
                key = bytes([random.randint(0, 255) for _ in range(len(shellcode))])
                generate_c_code(shellcode, key)
        elif choice == "3":
            print("\nScript Description:")
            print("This script encrypts shellcode using XOR encryption with a randomly generated key. ")
            print("The script outputs C-compatible arrays for the key and encrypted shellcode, which ")
            print("can be pasted into the provided C++ program. The C++ program will decrypt the shellcode")
            print("and execute it by XOR-ing the encrypted shellcode with the key.")
            print("\nUsage with the C Program:")
            print("1. Use this script to generate C code output for the key and encrypted shellcode.")
            print("2. Copy the output and paste it into the C program.")
            print("3. Compile and run the C program to execute the shellcode.")
        elif choice == "4":
            print("Exiting...")
            break
        else:
            print("Invalid choice. Please choose an option between 1-4.")

def handle_arguments():
    """terminal commands"""
    parser = argparse.ArgumentParser(description="Encrypt shellcode with XOR and generate C arrays.")
    parser.add_argument("-s", "--shellcode", help="Shellcode as a hex string (e.g., '\\x31\\xc0\\x50')")
    parser.add_argument("-f", "--file", help="Path to a file containing the shellcode in binary format")
    args = parser.parse_args()
    if args.shellcode:
        shellcode = bytes.fromhex(args.shellcode.replace("\\x", ""))
        key = bytes([random.randint(0, 255) for _ in range(len(shellcode))])
        generate_c_code(shellcode, key)
    elif args.file:
        shellcode = load_shellcode_from_file(args.file)
        if shellcode is not None:
            key = bytes([random.randint(0, 255) for _ in range(len(shellcode))])
            generate_c_code(shellcode, key)
    else:
        print("Error: Either --shellcode or --file option is required.")
        parser.print_help()

if __name__ == "__main__":
    if len(sys.argv) > 1:
        handle_arguments()
    else:
        main_menu()
