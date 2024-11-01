# toolbox_project:

    This toolbox project contains several scripts to use for pentesting. To start using the toolbox please open the main meny. from the meny you can navigate to whatever tool you want to use.
    It is of course also possible to use the tools seperately without the main meny. the toolbox is made to be usen in Windows enviroment but might work for Linux in som cases as well.
    all the tools can be usen with flags for one-line execution but also has menys for themselves.

## Dependencies:

    Please ensure that all dependencies are installed before trying to use the toolbox. the Dependencies can be found in the requirements.txt file.

    Installation on Windows:

    Installation on Windows:
    pip install -r requirements.txt

    Installation on Linux

    sudo pip install -r requirements.txt

## The scripts:

### Hash_bruteforce.py:
**About:**  
        This script can be used to bruteforce diffrent types of hashes (md5, bcrypt, argon2). The script requires a list of password to check against. for example rockyou.txt
        the script takes the following flags:
        hash: Input the hash to use.
        algorithm: Input the algorithm to use (md5, bcrypt, or argon2)
        -w or --wordlist: use to choose a wordlist (standard is wordlist.txt).
        -b or --bruteforce: if set, uses brute-force on a MD5-hash.
        -c or--charset: charset to use for bruteforce (only for MD5).
        -l or --length: Maximal length for password to test with bruteforce (only for MD5).

    Example usage:
        python hash_bruteforce.py 5f4dcc3b5aa765d61d8327deb882cf99 md5 -w wordlist.txt

        python hash_bruteforce.py $2b$12$C8.MQTxedNBi8BWWmM0XReh0ZCB5.k4d7N9t8w3CE0Z/uMnhKDWkW bcrypt -w wordlist.txt

        python hash_bruteforce.py $argon2id$v=19$m=102400,t=2,p=8$OTs2rGkTZgRxo9rNwXJyWA$Se0GnZj2iKe7MS8H0ZpKJw argon2 -w wordlist.txt

        python hash_bruteforce.py 5f4dcc3b5aa765d61d8327deb882cf99 md5 --bruteforce --charset abcdef --length 4

### Sniffer.py:
**About:**  
        This tool needs to be run as an administrator(win) or sudo(linux)
        Packet Sniffing and Manipulation: The script captures packets and manipulates them based on the user's input
        (e.g., modifying TCP flags, adjusting sequence numbers, or altering DNS query names).
        The DNS tunnel continuously sends DNS queries and displays responses from the server.
        the script takes the following arguments for sniff and manipulate.
            sniff
            -i or --interface: choose your network interface (e.g., eth0 or wlan0 on linux and Ethernet or Wi-Fi on windows)
            --tcp: filter tcp-packets
            --udp: filter udp-packets
            --icmp: filter icmp-packets
            -p or --port: choose port number (default is 80)
            -c or --count: Choose how many packages to capture (default is 10)
            output: choose output file to save results (optional)
            for dns tunneling:
            dnstunnel
            -s or --server Enter the DNS server (e.g., 8.8.8.8)
            -d or --domain: domain: Enter the domain to use for DNS queries
            output: Enter output file to save results (optional)

    Example usage:
        python script.py sniff -i eth0 --tcp --port 80 --count 5

        python script.py dnstunnel -s 8.8.8.8 -d example.com

### nmap_script.py:
**About:**  
        This tool allows you to do nmap scans and save results to file. this tool offers no features that cant be used directly throgh nmap.
        the script takes following arguments:
            --ip: set the IP address to scan
            --file: set a file to read ip adresses from
            --flags: set the flags to use when scanning
            --save: save the results to file

    Example usage:
        python nmap_script.py --ip 192.168.1.1 --flags "-sV" --save "output.txt"
        
### subdomain_enumeration_tool.py:
**About:**  
        This tool is designed for enumerating subdomains associated with a given domain using Python.
        It leverages Sublist3r for subdomain enumeration and requests to check subdomain availability. 
        Users can also load subdomains from a file, set specific scanning options, and save results.
        the script takes following arguments:
            -f or --file: set the file to save results to.
            --ports: set the port to scan.
            --bruteforce: enable bruteforce enumeration.
            --engines: set the search engines to use for subdomain discovery.
            -v or --verbose: enable verbose output.
            --load: load subdomains from file instead of enumeration.

    Example usage:
        enumeration:
        python subdomain_enum_tool.py example.com --ports 80,443 --bruteforce --engines google,bing -v -f results.txt

        check for availability of subdomains:
        python subdomain_enum_tool.py --load subdomains.txt -f checked_subdomains.txt -v

### crypt_shellcode.py:
 **About:**  
        This script encrypts shellcode using XOR and generates C-compatible unsigned char arrays for both the shellcode and the key.
        This is the supposed to be copied into the decrypt_shellcode.ccp file.
        The scripts takes the following arguments:
            -s or --shellcode: Shellcode in hex format as a string (e.g., "\\x31\\xc0\\x50").
            -k or --keylen: Length of the encryption key (should match shellcode length).

    Example usage:
        python encrypt_shellcode.py -s "\\x31\\xc0\\x50\\x68\\x2f\\x2f\\x73\\x68\\x68\\x2f\\x62\\x69\\x6e" -k 14

### decrypt_shellcode.ccp:
**About:**  
        This tool decrypts the provided encrypted shellcode using the generated key and executes it (shellcode and key need to be taken from crypt_shellcode.py).
        The program does not take command-line arguments but instead uses the key and encrypted shellcode hardcoded within it.
        Please note that this is made in c++ and not part of the main meny program.

    Example usage:
        gcc -o decrypt_shellcode decrypt_shellcode.c (compile the c program after adding shellcode and key)
        ./decrypt_shellcode (runs the script)

### generate_key.py:
**About:**  
        This tool generates a key to be used for encryption/decryption.

    Example usage:
        python generate_key.py keyfile

### crypto_tool.py:
**About:**  
        A tool to encrypt or decrypt files with keys generated from generate_key.py

    Example usage:
        python crypto_tool.py encrypt keyfile.key Encyptedfile.txt

        python crypto_tool.py decrypt keyfile.key Decyptedfile.txt

### kaffe_kontroll
**About:**  
        A reminder to drink coffe.

    Example usage:  
        just follow the instructions...


