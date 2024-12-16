import sys
import signal
from scapy.all import IP, UDP, DNS, DNSQR, sr1


# Colors
class bcolors:
    HEADER = "\033[95m"
    OKBLUE = "\033[94m"
    OKGREEN = "\033[92m"
    WARNING = "\033[93m"
    FAIL = "\033[91m"
    ENDC = "\033[0m"
    BOLD = "\033[1m"
    UNDERLINE = "\033[4m"


def def_handler(sig, frame):
    print(f"{bcolors.FAIL}\n\n[!] Quitting...\n{bcolors.ENDC}")
    sys.exit(1)


signal.signal(signal.SIGINT, def_handler)

# Initial configuration
namesever = "8.8.8.8"  # Google DNS
subdomains = [
    "www.upm.es",
    "vpn.etsiinf.upm.es",
    "correo.etsisi.upm.es",
    "e-administracion.upm.es",
    "www.marca.com",
    "seguro.marca.com",
    "videosar.marca.com",
    "amp.marca.com",
]
output_file = "dns_results.txt"


def dns_query(fqdn, nameserver):
    ip = IP(dst=nameserver)
    udp = ip / UDP(dport=53)
    dns = udp / DNS(rd=1, qd=DNSQR(qname=fqdn))
    answer = sr1(dns, verbose=0, timeout=5)
    if answer and answer.haslayer(DNS):
        ip_address = answer[DNS].an.rdata if answer[DNS].an else None
        return fqdn, ip_address
    return fqdn, None


def main():
    with open(output_file, "w") as f:
        for fqdn in subdomains:
            print(f"Scanning: {fqdn}")
            fqdn, ip_address = dns_query(fqdn, namesever)
            if ip_address:
                result = f"{fqdn} -> '{ip_address}'"
                print(f"{bcolors.OKGREEN}[*] {result}{bcolors.ENDC}\n")
                f.write(result + "\n")
            else:
                print(f"{bcolors.FAIL}[!] {fqdn} -> No IP found{bcolors.ENDC}\n")


if __name__ == "__main__":
    main()
