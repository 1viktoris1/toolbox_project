"""modules adds functions for terminal commands and symmetric authenticated cryptography """
import argparse
import sys
from cryptography.fernet import Fernet

def generate_key(output_file):
    """Generate a key"""
    key = Fernet.generate_key()
    with open(output_file, 'wb') as key_file:
        key_file.write(key)
    print(f"Key generated and saved to {output_file}")

def main_menu():
    """Main menu"""
    while True:
        print("\n--- Meny for key generation ---")
        print("1. Generate key and save to file")
        print("2. Exit")
        choice = input("\nChoose an option (1-2): ")
        if choice == "1":
            output_file = input("Choose name of file: ")
            generate_key(output_file)
        elif choice == "2":
            print("Exiting...")
            break
        else:
            print("Invalid choice, try again.")

if __name__ == "__main__":
    if len(sys.argv) > 1:
        parser = argparse.ArgumentParser(description="Generate a symmetrical key and save it to a file.")
        parser.add_argument("output_file", help="name of file where the key is stored")
        args = parser.parse_args()
        generate_key(args.output_file)
    else:
        main_menu()
