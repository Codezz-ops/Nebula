import requests
import ipaddress
import socket
import hashlib
import time
import socket
import random
import string
import platform
from flask import Flask, redirect
import threading

class System:
    class HelpMenu:
        @staticmethod
        def MainHelp():
            print('''
    Nebula Interactive Hacking Shell Help Menu

Commands:
    Subnet: Subnet Calculator
        Usage: Subnet [IP address] [Subnet Mask]

    IP: IP Lookup
        Usage: IP [IP address]

    hashident: Hash Identifier
        Usage: hashident [Hash value]

    whois: Whois Lookup
        Usage: whois [Domain name] or [IP address]

    nscan: Port Scanner
        Usage: nscan [IP address]

    URLcheck: URL Checker
        Usage: URLcheck [URL]

    passgen: Password Generator
        Usage: generate [Length of password (16)]
        
    DNS: DNS lookup
        usage: DNS [URL]
        
    buster: buster
        usage: buster [URL]
        
    hash: hash
        usage: hash [STRING] [ALGORITHM]''')

    def shorten(long_url):
        return url_shortener.shorten_url(long_url)
    
    def redirect(short_url):
        return url_shortener.redirect_url(short_url)
    
    def generate_password(length):
        chars = string.ascii_letters + string.digits + string.punctuation
        password = ''.join(random.choice(chars) for i in range(length))
        return password

    def Uname():
        print("System:", platform.system())
        print("Node Name:", platform.node())
        print("Release:", platform.release())
        print("Version:", platform.version())
        print("Machine:", platform.machine())
        print("Processor:", platform.processor())

class Tools:
    class URLshortener:
        def __init__(self):
            self.url_mapping = {}
            self.counter = 0

        @staticmethod
        def HelpMenu():
            print('Usage: URLshort <long_url>')
            print('       URLshort --help')
            print('')
            print('Options:')
            print('    <long_url>    URL to shorten')
            print('    --help        Display this help message and exit')
            print('')
            print('Examples:')
            print('    URLshort "https://www.example.com/long_url"')

        def generate_short_url(self, long_url):
            hash_object = hashlib.sha224(long_url.encode())
            hex_dig = hash_object.hexdigest()
            short_url = hex_dig[:8]
            self.counter += 1
            short_url = short_url + str(self.counter)
            self.url_mapping[short_url] = long_url
            return short_url

        def shorten_url(self, long_url):
            short_url = self.generate_short_url(long_url)
            return short_url

        def redirect_url(self, short_url):
            long_url = self.url_mapping.get(short_url)
            if long_url:
                return long_url
            else:
                return "Error: Invalid short URL"
            
    class Hashes:
        @staticmethod
        def HelpMenu():
            print('Usage: hash <string> <algorithm>')
            print('       hash --help')
            print('')
            print('Options:')
            print('    <string>    String to hash')
            print('    <algorithm> Algorithm to hash e.g(ms5, sha1)')
            print('    --help      Display this help message and exit')
            print('')
            print('Examples:')
            print('    hash "hello" md5')

        @staticmethod
        def hash_string(string, algorithm):
            if algorithm == 'md5':
                return hashlib.md5(string.encode()).hexdigest()
            elif algorithm == 'sha1':
                return hashlib.sha1(string.encode()).hexdigest()
            elif algorithm == 'sha256':
                return hashlib.sha256(string.encode()).hexdigest()
            else:
                return "Error: Unsupported algorithm"
    
    class DirBuster:
        @staticmethod
        def HelpMenu():
            print('Usage: buster <url>')
            print('       buster --help')
            print('')
            print('Options:')
            print('    <url>    URL of target link to scan')
            print('    --help   Display this help message and exit')
            print('')
            print('Examples:')
            print('    buster https://google.com')

        @staticmethod
        def directory_buster(url, wordlist):
            with open(wordlist, 'r') as f:
                for line in f:
                    line = line.strip()
                    target_url = url + '/' + line
                    try:
                        response = requests.get(target_url)
                        if response.status_code == 200:
                            print(f"[+] Found: {target_url}")
                    except Exception as e:
                        print(f"[-] Error: {e}")

    class DNSlookup:
        @staticmethod
        def HelpMenu():
            print('Usage: DNS <url>')
            print('       DNS --help')
            print('')
            print('Options:')
            print('    <url>    URL of target link to scan')
            print('    --help   Display this help message and exit')
            print('')
            print('Examples:')
            print('    DNS google.com')

        @staticmethod
        def lookup(url):
            records = ['A', 'AAAA', 'NS', 'MX', 'SOA', 'TXT']
            for record in records:
                try:
                    result = socket.getaddrinfo(url, None, socket.AF_INET, socket.SOCK_STREAM, socket.IPPROTO_TCP, socket.AI_CANONNAME)
                    print(f'{record} record: {result[0][4][0]}')
                except:
                    print(f'No {record} record found for {url}')

    class URLcheck:
        @staticmethod
        def HelpMenu():
            print('Usage: URLcheck <url>')
            print('       URLcheck --help')
            print('')
            print('Options:')
            print('    <url>    URL of target link to scan')
            print('    --help   Display this help message and exit')
            print('')
            print('Examples:')
            print('    URLcheck google.com')

        @staticmethod
        def url_checker(url):
            params = {'apikey': '17a21aa387fe99669dfd39a72519c886fd3ff1bbc6a92e81fcc1c9e09af21b8a', 'url':url}
            headers = {
                "Accept-Encoding": "gzip, deflate",
                "User-Agent" : "gzip,  My Python requests library example client or username"
            }

            # Send a post request to scan the URL
            response = requests.post('https://www.virustotal.com/vtapi/v2/url/scan', data=params, headers=headers)
            json_response = response.json()
            scan_id = json_response.get('scan_id', '')

            # Wait for 15 seconds before requesting the report
            time.sleep(15)

            # Get the report of the URL scan
            params = {'apikey': '17a21aa387fe99669dfd39a72519c886fd3ff1bbc6a92e81fcc1c9e09af21b8a', 'resource':scan_id}
            response = requests.post('https://www.virustotal.com/vtapi/v2/url/report', params=params, headers=headers)
            json_response = response.json()

            # Extract the required information from the response
            scan_id = json_response.get('scan_id', '')
            message = json_response.get('verbose_msg', '')
            permalink = json_response.get('permalink', '')

            # Format the result string
            result = "Scan ID: {}\nMessage: {}\nPermalink: {}".format(scan_id, message, permalink)
            print(result)

            positives = json_response.get('positives', '')
            total = json_response.get('total', '')
            result = "Positives: {}/{}".format(positives, total)
            print(result)

    class SubnetCalculator:
        @staticmethod
        def HelpMenu():
            print('Usage: Subnet <host> <submask>')
            print('       Subnet --help')
            print('')
            print('Options:')
            print('    <host>    Hostname or IP address of the target system')
            print('    <submask> Submask to scan (e.g. 16,32)')
            print('    --help    Display this help message and exit')
            print('')
            print('Examples:')
            print('    Subnet 1.1.1.1 16')

        def subnet_calculator(ip_address, subnet_mask):
            ip_network = ipaddress.ip_network(f"{ip_address}/{subnet_mask}", strict=False)
            network_address = ip_network.network_address
            broadcast_address = ip_network.broadcast_address
            num_hosts = ip_network.num_addresses - 2

            return (
                f"Network Address: {network_address}\n"
                f"Broadcast Address: {broadcast_address}\n"
                f"Subnet Mask: {subnet_mask}\n"
                f"Number of Hosts: {num_hosts}"
            )
    
    class IPLookup:
        @staticmethod
        def HelpMenu():
            print('Usage: IP <ip>')
            print('       IP --help')
            print('')
            print('Options:')
            print('    --help    Display this help message and exit')
            print('')
            print('Examples:')
            print('    IP 1.1.1.1')

        @staticmethod
        def ip_lookup(ip_address):
            response = requests.get(f"https://ipinfo.io/{ip_address}/json")
            data = response.json()
            return data
        
    class Hashid:
        @staticmethod
        def HelpMenu():
            print('Usage: hashident <hash>')
            print('       hashident --help')
            print('')
            print('Options:')
            print('    --help    Display this help message and exit')
            print('')
            print('Examples:')
            print('    hashident bf05dc40f68fca1a8bde12b0248d0f14')

        @staticmethod
        def hash_identifier(hash_string):
        # supported hash algorithms
            hash_types = {
                "md5": hashlib.md5(),
                "sha1": hashlib.sha1(),
                "sha224": hashlib.sha224(),
                "sha256": hashlib.sha256(),
                "sha384": hashlib.sha384(),
                "sha512": hashlib.sha512()
            }

            for ht in hash_types:
                if len(hash_string) == hash_types[ht].digest_size * 2:
                    if hash_types[ht].hexdigest() == hash_string:
                        return ht
            return "Unable to identify the hash type."
    
    class WhoisLookup:
        @staticmethod
        def HelpMenu():
            print('Usage: whois <host>')
            print('       whois --help')
            print('')
            print('Options:')
            print('    <host>    Hostname or IP address of the target system')
            print('    --help    Display this help message and exit')
            print('')
            print('Examples:')
            print('    whois example.com')
            print('    whois 192.168.1.1')

        @staticmethod
        def whois_lookup(domain_or_ip):
            whois_server = "whois.iana.org"
            port = 43

            try:
                is_ip = False
                try:
                    socket.inet_aton(domain_or_ip)
                    is_ip = True
                except:
                    pass
                
                if is_ip:
                    query = "n %s\r\n" % domain_or_ip
                else:
                    query = "%s\r\n" % domain_or_ip

                with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
                    s.connect((whois_server, port))
                    s.sendall(query.encode())
                    response = b''
                    while True:
                        data = s.recv(4096)
                        if not data:
                            break
                        response += data
                    print(response.decode())
            except Exception as e:
                print("Error Occured: ", e)
    
    class PortScanner:
        @staticmethod
        def HelpMenu():
            print('Usage: nscan <host> <ports>')
            print('       nscan --help')
            print('')
            print('Options:')
            print('    <host>    Hostname or IP address of the target system')
            print('    <flags>   Add flags to your scan (e.g. -sV)')
            print('    <ports>   Ports to scan, separated by commas (e.g. 22,80,443)')
            print('    --help    Display this help message and exit')
            print('')
            print('Examples:')
            print('    nscan example.com 22,80,443')
            print('    scan 192.168.1.1 22,80,443')

        def scan_host(host, port):
            try:
                s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                s.settimeout(0.1)
                result = s.connect_ex((host, port))
                if result == 0:
                    print("Port {} is open".format(port))
                s.close()
            except:
                print("Port {} is closed".format(port))

        def scan_ports(host, ports=None):
            if ports is None:
                ports = range(1, 65535)
            threads = []
            for port in ports:
                t = threading.Thread(target=Tools.PortScanner.scan_host, args=(host, port))
                threads.append(t)
                t.start()
            for t in threads:
                t.join()
                
url_shortener = Tools.URLshortener()
