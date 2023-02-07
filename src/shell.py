import os
import sys
import time
from classes import *

def Operating_System():
    if os.name != 'posix':
        print('This script is only intended for use on Unix-based systems.')
        sys.exit(1)
    else:
        shell()

def shell():
    while True:
        curr = time.ctime()
        print('\n' + curr)
        command = input('$ ')
        if command == 'exit':
            exit()
        elif command.startswith('nscan'):
            if len(command.split()) < 2:
                PortScanner.HelpMenu()
            elif command.split()[1] == '--help':
                PortScanner.HelpMenu()
            else:
                host = command.split()[1]
                try:
                    port_str = command.split()[2]
                    if port_str:
                        ports = [int(port) for port in port_str.split(',')]
                    else:
                        ports = None
                except IndexError:
                    ports = None
                except ValueError:
                    print("Ports must be numbers.")
                    PortScanner.HelpMenu()
                if ports:
                    PortScanner.scan_host(host, ports)
                else:
                    PortScanner.scan_ports(host)
        elif command.startswith('whois'):
                if len(command.split()) < 2:
                    WhoisLookup.HelpMenu()
                elif command.split()[1] == '--help':
                    WhoisLookup.HelpMenu()
                else:
                    domain_or_ip = command.split()[1]
                    WhoisLookup.whois_lookup(domain_or_ip)
        elif command.startswith('hashident'):
            if len(command.split()) < 2:
                Hashid.HelpMenu()
            elif command.split()[1] == '--help':
                Hashid.HelpMenu()
            else:
                hash_input = command.split()[1]
                print(Hashid.hash_identifier(hash_input))
        elif command == 'uname -f':
            Defaults.Uname()
        elif command.startswith('IP'):
            if len(command.split()) < 2:
                IPLookup.HelpMenu()
            elif command.split()[1] == '--help':
                IPLookup.HelpMenu()
            else:
                ip_address = command.split()[1]
                data = IPLookup.ip_lookup(ip_address)
                print(f"Location: {data['city']}, {data['region']}, {data['country']}")
                print(f"ISP: {data['org']}")
                print(f"Location: {data['loc']}")
                print(f"Postal Code: {data['postal']}")
        elif command.startswith('Subnet'):
            if len(command.split()) < 2:
                SubnetCalculator.HelpMenu()
            elif command.split()[1] == '--help':
                SubnetCalculator.HelpMenu()
            else:
                ip_address = command.split()[1]
                subnet_mask = command.split()[2]
                print(SubnetCalculator.subnet_calculator(ip_address, subnet_mask))
        elif command == 'passgen':
            print('Password: ' + Defaults.generate_password(16))
        elif command.startswith('URLcheck'):
            if len(command.split()) < 2:
                URLcheck.HelpMenu()
            elif command.split()[1] == '--help':
                URLcheck.HelpMenu()
            else:
                url = command.split()[1]
                URLcheck.url_checker(url)
        elif command == 'help':
            HelpMenu.MainHelp()
        elif command.startswith('DNS'):
            if len(command.split()) < 2:
                DNSlookup.HelpMenu()
            elif command.split()[1] == '--help':
                DNSlookup.HelpMenu()
            else:
                url = command.split()[1]
                DNSlookup.DNSlookup(url)
        elif command.startswith('buster'):
            if len(command.split()) < 2:
                DirBuster.HelpMenu()
            elif command.split()[1] == '--help':
                DirBuster.HelpMenu()
            else:
                wordlist = 'wordlist.txt'
                url = command.split()[1]
                DirBuster.directory_buster(url, wordlist)
        elif command.startswith('hash'):
            if len(command.split()) < 2:
                Hashes.HelpMenu()
            elif command.split()[1] == '--help':
                Hashes.HelpMenu()
            else:
                string = command.split()[1]
                algorithm = command.split()[2]
                print(Hashes.hash_string(string, algorithm))
        elif command.startswith('URLshort'):
            if len(command.split()) < 2:
                URLshortener.HelpMenu()
            elif command.split()[1] == '--help':
                URLshortener.HelpMenu()
            else:
                long_url = command.split()[1]
                url_shortener = URLshortener()
                short_url = url_shortener.shorten_url(long_url)
                print(f"Short URL: {short_url}")
                print(f"Redirect URL: {url_shortener.redirect_url(short_url)}")
        else:
            os.system(command)

if __name__ == '__main__':
    Operating_System()
