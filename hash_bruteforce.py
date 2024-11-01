"""Creating iterators for efficient looping, terminal commands and add cryptation support"""
import sys
import itertools
import argparse
import hashlib
import bcrypt
import argon2

def crack_hash_md5(hash_value, wordlist):
    """Bruteforce md5-hash"""
    with open(wordlist, 'r') as f:
        for word in f:
            word = word.strip()
            if hashlib.md5(word.encode()).hexdigest() == hash_value:
                return word
    return None

def crack_hash_bcrypt(hash_value, wordlist):
    """Bruteforce bcrypt-hash"""
    with open(wordlist, 'r') as f:
        for word in f:
            word = word.strip()
            if bcrypt.checkpw(word.encode(), hash_value.encode()):
                return word
    return None

def crack_hash_argon2(hash_value, wordlist):
    """Bruteforce argon2-hash"""
    ph = argon2.PasswordHasher()
    with open(wordlist, 'r') as f:
        for word in f:
            word = word.strip()
            try:
                ph.verify(hash_value, word)
                return word
            except argon2.exceptions.VerifyMismatchError:
                continue
    return None

def brute_force_md5(hash_value, charset, max_length):
    """Bruteforce attack with itertools"""
    for length in range(1, max_length + 1):
        for guess in itertools.product(charset, repeat=length):
            guess_word = ''.join(guess)
            if hashlib.md5(guess_word.encode()).hexdigest() == hash_value:
                return guess_word
    return None

def load_hashes_from_file(filename):
    """Load hashes from file"""
    with open(filename, 'r') as file:
        hashes = [line.strip() for line in file]
    return hashes

def save_result_to_file(result, filename):
    """saves to file"""
    with open(filename, 'a') as file:
        file.write(result + '\n')
    print(f"[+] Saved to {filename}")

def show_main_menu():
    """Show the main menu"""
    print("Main menu:")
    print("1. Bruteforce hash from file")
    print("2. Bruteforce hash from input")
    print("3. Exit")
    choice = input("choose 1-3: ")
    if choice == "1":
        filename = input("what is the name of the file?: ")
        hashes = load_hashes_from_file(filename)
        for hash_value in hashes:
            run_cracking_process(hash_value)
    elif choice == "2":
        hash_value = input("what is the hash to bruteforce?: ")
        run_cracking_process(hash_value)
    elif choice == "3":
        print("Exiting...")
        sys.exit()
    else:
        print("Invalid choice. Please try again.")
        show_main_menu()

def main():
    """Main function"""
    if len(sys.argv) > 1:
        parser = argparse.ArgumentParser(description="Bruteforcing passwords with diffrent hash-algorithms.")
        parser.add_argument("hash", help="The hash to bruteforce")
        parser.add_argument("algorithm", choices=["md5", "bcrypt", "argon2"], help="Hash-algorithm to use")
        parser.add_argument("-w", "--wordlist", help="pathway to the wordlist you want to use", default="wordlist.txt")
        parser.add_argument("-b", "--bruteforce", action="store_true", help="Execute bruteforce attack (MD5 only)")
        parser.add_argument("-c", "--charset", help="Charset for bruteforce (MD5 only)", default="abcdefghijklmnopqrstuvwxyz")
        parser.add_argument("-l", "--length", type=int, help="Maximal password length for bruteforce (MD5 only)", default=6)
        args = parser.parse_args()
        if args.hashfile:
            hashes = load_hashes_from_file(args.hashfile)
            for hash_value in hashes:
                result = run_cracking_process(hash_value, args)
                if result:
                    save_result_to_file(f"{hash_value} : {result}", args.output)
        else:
            result = run_cracking_process(args.hash, args)
            if result:
                save_result_to_file(f"{args.hash} : {result}", args.output)
    else:
        show_main_menu()

def run_cracking_process(hash_value, args=None):
    """Handle CRACKING process"""
    if args:
        algorithm = args.algorithm
        wordlist = args.wordlist
        charset = args.charset
        length = args.length
        bruteforce = args.bruteforce
    else:
        algorithm = input("Choose algorithm (md5, bcrypt, argon2): ")
        wordlist = input("Choose wordlist (Standard is wordlist.txt): ") or "wordlist.txt"
        bruteforce = input("do you want to use bruteforce foy MD5 (yes/no)? ").lower() == "yes"
        charset = "abcdefghijklmnopqrstuvwxyz"
        length = 6
    if algorithm == "md5":
        if bruteforce:
            print("\nBruteforce attack on MD5...")
            return brute_force_md5(hash_value, charset, length)
        else:
            print("\nBruteforcing MD5-hash...")
            return crack_hash_md5(hash_value, wordlist)
    elif algorithm == "bcrypt":
        print("\nBruteforcing bcrypt-hash...")
        return crack_hash_bcrypt(hash_value, wordlist)
    elif algorithm == "argon2":
        print("\nBruteforcing argon2-hash...")
        return crack_hash_argon2(hash_value, wordlist)
    else:
        print("[-] no valid algorithm choosen")
        return None

if __name__ == "__main__":
    main()
