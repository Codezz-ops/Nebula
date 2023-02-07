import os
import sys
import time
from classes import *

def Operating_System():
    if os.name != "posix":
        print("This script is only intended for use on Unix-based systems.")
        sys.exit(1)
    else:
        shell()


def shell():
    while True:
        curr = time.ctime()
        print("\n" + curr)
        command = input("$ ")
        if command == "exit":
            exit()

        elif command.startswith("nscan"):
            if len(command.split()) < 2:
                Tools.PortScanner.HelpMenu()

            elif command.split()[1] == "--help":
                Tools.PortScanner.HelpMenu()
            else:
                host = command.split()[1]
                try:
                    port_str = command.split()[2]
                    if port_str:
                        ports = [int(port) for port in port_str.split(",")]
                    else:
                        ports = None
                except IndexError:
                    ports = None
                except ValueError:
                    print("Ports must be numbers.")
                    Tools.PortScanner.HelpMenu()
                if ports:
                    Tools.PortScanner.scan_host(host, ports)
                else:
                    Tools.PortScanner.scan_ports(host)

        elif command.startswith("whois"):
            if len(command.split()) < 2:
                Tools.WhoisLookup.HelpMenu()
            elif command.split()[1] == "--help":
                Tools.WhoisLookup.HelpMenu()
            else:
                domain_or_ip = command.split()[1]
                Tools.WhoisLookup.whois_lookup(domain_or_ip)

        elif command.startswith("hashident"):
            if len(command.split()) < 2:
                Tools.Hashid.HelpMenu()
            elif command.split()[1] == "--help":
                Tools.Hashid.HelpMenu()
            else:
                hash_input = command.split()[1]
                print(Tools.Hashid.hash_identifier(hash_input))

        elif command == "uname -f":
            System.Uname()
        elif command.startswith("IP"):
            if len(command.split()) < 2:
                Tools.IPLookup.HelpMenu()
            elif command.split()[1] == "--help":
                Tools.IPLookup.HelpMenu()
            else:
                ip_address = command.split()[1]
                data = Tools.IPLookup.ip_lookup(ip_address)
                print(f"Location: {data['city']}, {data['region']}, {data['country']}")
                print(f"ISP: {data['org']}")
                print(f"Location: {data['loc']}")
                print(f"Postal Code: {data['postal']}")

        elif command.startswith("Subnet"):
            if len(command.split()) < 2:
                Tools.SubnetCalculator.HelpMenu()
            elif command.split()[1] == "--help":
                Tools.SubnetCalculator.HelpMenu()
            else:
                ip_address = command.split()[1]
                subnet_mask = command.split()[2]
                print(Tools.SubnetCalculator.subnet_calculator(ip_address, subnet_mask))

        elif command == "passgen":
            print("Password: " + System.generate_password(16))
        elif command.startswith("URLcheck"):
            if len(command.split()) < 2:
                Tools.URLcheck.HelpMenu()
            elif command.split()[1] == "--help":
                Tools.URLcheck.HelpMenu()
            else:
                url = command.split()[1]
                Tools.URLcheck.url_checker(url)

        elif command == "help":
            System.HelpMenu.MainHelp()

        elif command.startswith("DNS"):
            if len(command.split()) < 2:
                Tools.DNSlookup.HelpMenu()
            elif command.split()[1] == "--help":
                Tools.DNSlookup.HelpMenu()
            else:
                url = command.split()[1]
                Tools.DNSlookup.lookup(url)

        elif command.startswith("buster"):
            if len(command.split()) < 2:
                Tools.DirBuster.HelpMenu()
            elif command.split()[1] == "--help":
                Tools.DirBuster.HelpMenu()
            else:
                wordlist = "wordlist.txt"
                url = command.split()[1]
                Tools.DirBuster.directory_buster(url, wordlist)

        elif command.startswith("hash"):
            if len(command.split()) < 2:
                Tools.Hashes.HelpMenu()
            elif command.split()[1] == "--help":
                Tools.Hashes.HelpMenu()
            else:
                string = command.split()[1]
                algorithm = command.split()[2]
                print(Tools.Hashes.hash_string(string, algorithm))

        elif command.startswith("URLshort"):
            if len(command.split()) < 2:
                Tools.URLshortener.HelpMenu()
            elif command.split()[1] == "--help":
                Tools.URLshortener.HelpMenu()
            else:
                long_url = command.split()[1]
                url_shortener = Tools.URLshortener()
                short_url = url_shortener.shorten_url(long_url)
                print(f"Short URL: {short_url}")
                print(f"Redirect URL: {url_shortener.redirect_url(short_url)}")
        else:
            os.system(command)


if __name__ == "__main__":
    Operating_System()
