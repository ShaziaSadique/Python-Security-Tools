"""
Professional TCP Connect Port Scanner
--------------------------------------
Performs a multithreaded TCP connect scan (full three-way handshake,
similar to Nmap's -sT) against a target host, grabs service banners
on open ports, and writes results to a report file.

Author: Shazia Sadique
"""

import socket
import threading
import argparse
import time
import sys
from queue import Queue, Empty
from colorama import Fore, Style, init

init(autoreset=True)

# Shared state across threads
port_queue = Queue()
open_ports = []
lock = threading.Lock()
stop_event = threading.Event()

COMMON_SERVICES = {
    20: "FTP Data",
    21: "FTP",
    22: "SSH",
    23: "Telnet",
    25: "SMTP",
    53: "DNS",
    80: "HTTP",
    110: "POP3",
    111: "RPC",
    135: "MSRPC",
    139: "NetBIOS",
    143: "IMAP",
    443: "HTTPS",
    445: "SMB",
    3306: "MySQL",
    3389: "RDP",
    5432: "PostgreSQL",
    5900: "VNC",
    6379: "Redis",
    8080: "HTTP Proxy",
}

# Ports where sending an HTTP HEAD request is meaningful
HTTP_LIKE_PORTS = {80, 8080, 443, 8443, 8000, 8888}


def banner_grab(ip, port, timeout=1):
    """
    Attempt to read a service banner from an open port.

    Strategy:
    1. Connect and try a passive read first -- many services (SSH,
       FTP, SMTP, etc.) send a greeting banner immediately on connect
       without requiring any input.
    2. If nothing comes back and the port is a known HTTP-like port,
       send a minimal HEAD request and read the response.
    3. Otherwise, give up gracefully and return an empty string.

    Returns a truncated, single-line string, or "" if nothing
    could be read.
    """
    try:
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
            s.settimeout(timeout)
            s.connect((ip, port))

            # Step 1: passive read for services that greet on connect
            try:
                s.settimeout(timeout)
                banner = s.recv(1024)
                if banner:
                    return banner.decode(errors="ignore").strip().replace("\n", " ")[:60]
            except socket.timeout:
                pass

            # Step 2: active probe for HTTP-like services
            if port in HTTP_LIKE_PORTS:
                try:
                    s.send(b"HEAD / HTTP/1.0\r\n\r\n")
                    banner = s.recv(1024)
                    return banner.decode(errors="ignore").strip().replace("\n", " ")[:60]
                except (socket.timeout, OSError):
                    return ""

            return ""
    except (socket.timeout, ConnectionRefusedError, OSError):
        return ""


def scan_worker(ip, timeout, grab_banner):
    """
    Worker function run by each thread. Pulls ports from the shared
    queue until it is empty or a stop is requested, attempts a TCP
    connect scan on each, and records any open ports found.
    """
    while not stop_event.is_set():
        try:
            port = port_queue.get_nowait()
        except Empty:
            break

        try:
            with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
                sock.settimeout(timeout)
                result = sock.connect_ex((ip, port))

                if result == 0:
                    service = COMMON_SERVICES.get(port, "Unknown")
                    banner = banner_grab(ip, port, timeout) if grab_banner else ""

                    with lock:
                        open_ports.append((port, service, banner))
                        print(
                            f"{Fore.GREEN}[OPEN]{Style.RESET_ALL} "
                            f"{port:<6} {service:<15} {banner}"
                        )
        except (socket.timeout, ConnectionRefusedError, OSError):
            pass
        finally:
            port_queue.task_done()


def validate_args(args):
    """Validate CLI arguments before starting the scan. Returns an error string, or None if valid."""
    if args.start < 1 or args.end > 65535:
        return "Ports must be between 1 and 65535."
    if args.start > args.end:
        return "Start port cannot be greater than end port."
    if args.threads < 1 or args.threads > 1000:
        return "Thread count must be between 1 and 1000."
    if args.timeout <= 0:
        return "Timeout must be greater than 0."
    return None


def run_scan(target, ip, args):
    """Queue ports, spin up worker threads, and wait for completion or interrupt."""
    for port in range(args.start, args.end + 1):
        port_queue.put(port)

    threads = []
    for _ in range(args.threads):
        t = threading.Thread(
            target=scan_worker,
            args=(ip, args.timeout, not args.no_banner),
            daemon=True,
        )
        t.start()
        threads.append(t)

    # Poll instead of a blocking join() so Ctrl+C is caught promptly
    try:
        while any(t.is_alive() for t in threads):
            for t in threads:
                t.join(timeout=0.2)
    except KeyboardInterrupt:
        print(f"\n{Fore.YELLOW}[!] Scan interrupted by user. Stopping threads...{Style.RESET_ALL}")
        stop_event.set()
        for t in threads:
            t.join(timeout=1)
        return False

    return True


def write_report(target, ip, args, elapsed, completed):
    """Write scan results to a report file."""
    filename = args.output or f"{target.replace('.', '_')}_scan.txt"

    with open(filename, "w") as f:
        f.write("Professional TCP Connect Port Scanner - Report\n")
        f.write("=" * 50 + "\n")
        f.write(f"Target    : {target}\n")
        f.write(f"IP        : {ip}\n")
        f.write(f"Ports     : {args.start}-{args.end}\n")
        f.write(f"Status    : {'Completed' if completed else 'Interrupted'}\n")
        f.write(f"Time      : {elapsed:.2f} seconds\n\n")
        f.write(f"{'PORT':<8}{'SERVICE':<17}{'BANNER'}\n")
        f.write("-" * 50 + "\n")
        for port, service, banner in sorted(open_ports):
            f.write(f"{port:<8}{service:<17}{banner}\n")

    return filename


def main():
    parser = argparse.ArgumentParser(
        description="Professional TCP Connect Port Scanner"
    )
    parser.add_argument("-t", "--target", required=False, help="Target IP or hostname")
    parser.add_argument("-s", "--start", type=int, default=1, help="Start port (default: 1)")
    parser.add_argument("-e", "--end", type=int, default=1024, help="End port (default: 1024)")
    parser.add_argument("-th", "--threads", type=int, default=100, help="Number of threads (default: 100)")
    parser.add_argument("-o", "--output", default=None, help="Output filename (default: auto-generated)")
    parser.add_argument("--timeout", type=float, default=1.0, help="Per-connection timeout in seconds (default: 1.0)")
    parser.add_argument("--no-banner", action="store_true", help="Skip banner grabbing (faster scan)")

    args = parser.parse_args()

    target = args.target or input("Enter target IP or hostname: ").strip()
    if not target:
        print("No target provided. Exiting.")
        sys.exit(1)

    error = validate_args(args)
    if error:
        print(f"Invalid arguments: {error}")
        sys.exit(1)

    try:
        ip = socket.gethostbyname(target)
    except socket.gaierror:
        print(f"Unable to resolve target: {target}")
        sys.exit(1)

    print("=" * 55)
    print("Professional TCP Connect Port Scanner")
    print("=" * 55)
    print(f"Target  : {target}")
    print(f"IP      : {ip}")
    print(f"Ports   : {args.start}-{args.end}")
    print(f"Threads : {args.threads}")
    print()

    start_time = time.time()
    completed = run_scan(target, ip, args)
    elapsed = time.time() - start_time

    filename = write_report(target, ip, args, elapsed, completed)

    print(f"\n{'Scan Completed' if completed else 'Scan Interrupted'}")
    print(f"Open Ports : {len(open_ports)}")
    print(f"Time Taken : {elapsed:.2f} seconds")
    print(f"Results saved to {filename}")

    sys.exit(0 if completed else 130)


if __name__ == "__main__":
    main()