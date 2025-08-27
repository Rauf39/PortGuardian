import nmap
from datetime import datetime

def scan_target(target, ports="1-1024"):
    scanner = nmap.PortScanner()
    print(f"🔎 Scanning {target} on ports {ports} ...\n")
    results = []

    try:
        scanner.scan(target, ports)
    except Exception as e:
        print(f"❌ Error: {e}")
        return []

    for host in scanner.all_hosts():
        print(f"\nHost: {host} ({scanner[host].hostname()})")
        print(f"State: {scanner[host].state()}")
        for proto in scanner[host].all_protocols():
            lport = scanner[host][proto].keys()
            for port in sorted(lport):
                state = scanner[host][proto][port]['state']
                name = scanner[host][proto][port]['name']
                result = {
                    "host": host,
                    "port": port,
                    "state": state,
                    "service": name
                }
                results.append(result)
                print(f" ➤ Port {port}: {state} ({name})")
    return results


def save_report(results, filename="scan_report.txt"):
    with open(filename, "w") as f:
        f.write(f"PortGuardian Scan Report - {datetime.now()}\n")
        f.write("="*50 + "\n\n")
        for r in results:
            f.write(f"Host: {r['host']} | Port: {r['port']} | State: {r['state']} | Service: {r['service']}\n")
    print(f"\n✅ Report saved to {filename}")


if __name__ == "__main__":
    target = input("Enter target IP or hostname: ")
    port_range = input("Enter port range (default 1-1024): ") or "1-1024"
    results = scan_target(target, port_range)
    if results:
        save_report(results, "scan_report.txt")
