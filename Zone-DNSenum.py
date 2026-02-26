import dns.resolver
import dns.query
import dns.zone
import threading
import queue
import argparse
import os
from concurrent.futures import ThreadPoolExecutor

# --- Globals ---
discovered_domains = set()
found_records = [] 
lock = threading.Lock()
file_lock = threading.Lock() 
task_queue = queue.Queue()

def get_resolver(server):
    resolver = dns.resolver.Resolver()
    resolver.nameservers = [server]
    resolver.timeout = 1
    resolver.lifetime = 1
    return resolver

def write_to_file(file_path, domain, ip):
    """Safely writes result in 'domain ip' format to the output file."""
    if file_path:
        data = f"{domain} {ip}"
        with file_lock:
            with open(file_path, 'a') as f:
                f.write(data + "\n")

def check_single_sub(sub, parent_domain, depth, executor, args):
    """Worker function for DNS brute-forcing."""
    fqdn = f"{sub}.{parent_domain}"
    resolver = get_resolver(args.server)
    try:
        answers = resolver.resolve(fqdn, 'A')
        for rdata in answers:
            print(f"\033[0;32m[+] Found:\033[0m {fqdn} -> {rdata.address}")
            
            with lock:
                found_records.append((fqdn, rdata.address, "Brute-force"))
            
            write_to_file(args.output, fqdn, rdata.address)
            
            # Recurse on the discovered subdomain if depth permits
            task_queue.put(1)
            executor.submit(recursive_enum, fqdn, depth + 1, executor, args)
    except:
        pass
    finally:
        task_queue.task_done()

def recursive_enum(domain, depth, executor, args):
    """
    Core Recursive Engine:
    1. Attempts AXFR (Zone Transfer).
    2. If AXFR fails, falls back to multi-threaded brute-force.
    """
    clean_domain = domain.lstrip('@.').rstrip('.')

    with lock:
        if depth > args.depth or clean_domain in discovered_domains:
            task_queue.task_done()
            return
        discovered_domains.add(clean_domain)

    print(f"\033[1;34m[*] Analyzing: {clean_domain} (Depth: {depth})\033[0m")

    # 1. Attempt AXFR
    axfr_success = False
    try:
        xfr_query = dns.query.xfr(args.server, clean_domain, timeout=2)
        zone = dns.zone.from_xfr(xfr_query)
        if zone:
            print(f"\033[1;32m[!] AXFR SUCCESS: {clean_domain}\033[0m")
            axfr_success = True
            for name, node in zone.nodes.items():
                s_name = str(name)
                if s_name in ["@", "*", ""]: continue
                full_name = f"{s_name}.{clean_domain}".rstrip('.')
                
                # Log A records found within the zone transfer
                for rdataset in node.rdatasets:
                    if rdataset.rdtype == dns.rdatatype.A:
                        for rdata in rdataset:
                            with lock:
                                found_records.append((full_name, rdata.address, "AXFR"))
                            write_to_file(args.output, full_name, rdata.address)

                # Queue recursion for discovered sub-zones or hosts
                task_queue.put(1)
                executor.submit(recursive_enum, full_name, depth + 1, executor, args)
    except:
        axfr_success = False

    # 2. Brute-force Fallback (Only if AXFR was not possible)
    if not axfr_success and depth < args.depth:
        try:
            with open(args.wordlist, 'r') as f:
                for line in f:
                    sub = line.strip()
                    if sub and not sub.startswith('#'):
                        task_queue.put(1)
                        executor.submit(check_single_sub, sub, clean_domain, depth, executor, args)
        except FileNotFoundError:
            print(f"\033[1;31m[!] Error:\033[0m Wordlist file not found.")

    task_queue.task_done()

def main():
    parser = argparse.ArgumentParser(description="Zone-DNSenum: Recursive DNS Zone Transfer & Enumerator")
    parser.add_argument("-d", "--domain", required=True, help="Domain to enumerate")
    parser.add_argument("-s", "--server", required=True, help="DNS server IP")
    parser.add_argument("-w", "--wordlist", required=True, help="Wordlist for brute-forcing")
    parser.add_argument("-t", "--threads", type=int, default=40, help="Concurrent threads (default: 40)")
    parser.add_argument("--depth", type=int, default=3, help="Max recursion depth (default: 3)")
    parser.add_argument("-o", "--output", help="Output file (Format: domain ip)")

    args = parser.parse_args()

    # Clear output file if specified
    if args.output:
        with open(args.output, 'w') as f:
            pass 

    print(f"\033[1;35m[ START ] Zone-DNSenum - Target: {args.domain}\033[0m")
    
    try:
        with ThreadPoolExecutor(max_workers=args.threads) as executor:
            task_queue.put(1)
            executor.submit(recursive_enum, args.domain, 1, executor, args)
            
            # Keep main thread alive until all recursive tasks complete
            task_queue.join()
            
    except KeyboardInterrupt:
        print("\n\033[1;31m[!] Interrupted by user. Exiting immediately...\033[0m")
        os._exit(0)

    # --- Result Summary Table ---
    print(f"\n\033[1;35m[ FINISHED ] Enumeration complete.\033[0m")
    if found_records:
        print(f"{'DOMAIN':<45} {'IP ADDRESS':<15} {'METHOD'}")
        print("-" * 75)
        for dom, ip, method in sorted(found_records, key=lambda x: x[0]):
            method_style = f"\033[1;32m{method}\033[0m" if method == "AXFR" else method
            print(f"{dom:<45} {ip:<15} {method_style}")
    else:
        print("[!] No DNS records were identified.")
    
    if args.output:
        print(f"\n[*] All discoveries saved to: {args.output}")

if __name__ == "__main__":
    main()