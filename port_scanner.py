import argparse
import socket
import logging
import concurrent.futures
import ipaddress
import time
import json
import csv
import os
from datetime import datetime
from sys import stdout

# ANSI Colors for terminal output
class Config:
    COLORS_ENABLED = True

class Colors:
    HEADER = '\033[95m'
    OKBLUE = '\033[94m'
    OKCYAN = '\033[96m'
    OKGREEN = '\033[92m'
    WARNING = '\033[93m'
    FAIL = '\033[91m'
    ENDC = '\033[0m'
    BOLD = '\033[1m'

def colorize(text, color):
    # Only use colors if enabled and not writing to a pure raw file stream
    if Config.COLORS_ENABLED:
        return f"{color}{text}{Colors.ENDC}"
    return text

# Set up logging context
def setup_logging(log_file='port_scanner.log'):
    logger = logging.getLogger('port_scanner')
    logger.setLevel(logging.INFO)
    logger.handlers = [] # Clear existing handlers to prevent duplicates
    
    # File handler records everything without ANSI escape codes for clean files
    file_handler = logging.FileHandler(log_file)
    file_handler.setLevel(logging.INFO)
    file_formatter = logging.Formatter('%(asctime)s - %(message)s')
    file_handler.setFormatter(file_formatter)
    
    # Console handler records with minimal clutter
    console_handler = logging.StreamHandler(stdout)
    console_handler.setLevel(logging.INFO)
    console_formatter = logging.Formatter('%(message)s')
    console_handler.setFormatter(console_formatter)
    
    logger.addHandler(file_handler)
    logger.addHandler(console_handler)
    
    return logger

logger = None # Will initialize dynamically

def print_banner():
    banner = f"""
    ____             __     __  __                     __            
   / __ \____  _____/ /_   / / / /__  _  ______  _____/ /_____  _____
  / /_/ / __ \/ ___/ __/  / /_/ / __ \| |/_/ __ \/ ___/ //_/ / / / ___/
 / ____/ /_/ / /  / /_   / __  / /_/ />  </ /_/ / /  / ,< / /_/ / /    
/_/    \____/_/   \__/  /_/ /_/\____/_/|_|\____/_/  /_/|_|\__,_/_/     
                                                                       
    """
    if Config.COLORS_ENABLED:
        print(f"{Colors.OKCYAN}{Colors.BOLD}{banner}{Colors.ENDC}")
    else:
        print(banner)
    print("=" * 70)
    print(" Advanced TCP Port Scanner & Banner Grabber ".center(70, "="))
    print("=" * 70)

def strip_ansi_codes(text):
    """Strip ANSI color codes for file logging"""
    import re
    ansi_escape = re.compile(r'\x1B(?:[@-Z\\-_]|\[[0-?]*[ -/]*[@-~])')
    return ansi_escape.sub('', text)

def log_msg(msg, level='info'):
    """Custom logger that strips ANSI codes before writing to log file."""
    clean_msg = strip_ansi_codes(msg)
    
    # Write directly to console with colors
    if level == 'info':
        print(msg)
    elif level == 'error':
        print(msg)
    elif level == 'warning':
        print(msg)
        
    # Write to file without colors
    for handler in logging.getLogger('port_scanner').handlers:
        if isinstance(handler, logging.FileHandler):
            # Formatter adds timestamp
            record = logging.LogRecord('port_scanner', logging.INFO if level=='info' else logging.ERROR, '', 0, clean_msg, (), None)
            handler.emit(record)

def resolve_host(host):
    try:
        ipaddress.ip_address(host)
        return host
    except ValueError:
        try:
            ip = socket.gethostbyname(host)
            return ip
        except socket.gaierror:
            return None

def grab_banner(s, port):
    """Attempt to grab the banner from the service."""
    try:
        # Some services require us to send data first (e.g., HTTP)
        if port in [80, 443, 8080, 8443]:
            s.sendall(b"HEAD / HTTP/1.0\r\n\r\n")
        
        banner = s.recv(1024).decode('utf-8', errors='ignore').strip()
        # Keep only the first line of the banner to avoid huge multi-line responses
        if banner:
            return banner.split('\n')[0][:50]
        return ""
    except Exception:
        return ""

def scan_port(ip, port, timeout=1.0, grab=False):
    result = {
        'port': port,
        'status': 'closed',
        'service': 'unknown',
        'banner': ''
    }
    
    try:
        # Get common service name
        try:
            result['service'] = socket.getservbyport(port, 'tcp')
        except OSError:
            pass
            
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
            s.settimeout(timeout)
            
            # Record time for connection testing
            start_time = time.time()
            connection_result = s.connect_ex((ip, port))
            end_time = time.time()
            
            if connection_result == 0:
                result['status'] = 'open'
                
                # Format output message
                svc_str = f"[{result['service']}]"
                msg = f"  [+] Port {str(port).ljust(5)}/tcp is {colorize('OPEN', Colors.OKGREEN)} {svc_str.ljust(15)} ({(end_time-start_time)*1000:.1f}ms)"
                
                # Attempt to grab banner if requested
                if grab:
                    s.settimeout(max(0.5, timeout/2))
                    banner = grab_banner(s, port)
                    if banner:
                        result['banner'] = banner
                        msg += f" | Banner: {colorize(banner, Colors.OKCYAN)}"
                        
                log_msg(msg)
                
    except socket.timeout:
        result['status'] = 'filtered'
    except socket.error as e:
        result['status'] = f'error ({str(e)})'
    except Exception as e:
        result['status'] = f'error'
        
    return result

def parse_ports(port_string):
    ports = set()
    parts = port_string.split(',')
    
    for part in parts:
        part = part.strip()
        if not part: continue
        if '-' in part:
            try:
                start, end = map(int, part.split('-', 1))
                if 1 <= start <= end <= 65535:
                    ports.update(range(start, end + 1))
            except ValueError:
                pass
        else:
            try:
                port = int(part)
                if 1 <= port <= 65535:
                    ports.add(port)
            except ValueError:
                pass
                
    return sorted(list(ports))

def save_results(results, target_ip, target_host, output_format):
    timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
    open_results = [r for r in results if r['status'] == 'open']
    
    if output_format == 'json':
        filename = f"scan_{target_ip}_{timestamp}.json"
        data = {
            "target": target_host,
            "ip": target_ip,
            "timestamp": timestamp,
            "open_ports": open_results
        }
        with open(filename, 'w') as f:
            json.dump(data, f, indent=4)
        log_msg(f"\n{colorize('[*]', Colors.OKBLUE)} Results saved to {filename}")
        
    elif output_format == 'csv':
        filename = f"scan_{target_ip}_{timestamp}.csv"
        with open(filename, 'w', newline='') as f:
            writer = csv.DictWriter(f, fieldnames=['port', 'status', 'service', 'banner'])
            writer.writeheader()
            writer.writerows(open_results)
        log_msg(f"\n{colorize('[*]', Colors.OKBLUE)} Results saved to {filename}")

def main():
    if os.name == 'nt':
        os.system('color')
        
    parser = argparse.ArgumentParser(description="Advanced Multi-threaded TCP Port Scanner.")
    parser.add_argument("host", help="Hostname or IP address to scan")
    parser.add_argument("-p", "--ports", default="1-1024", 
                        help="Ports to scan (e.g., '80', '80,443', '1-1024').")
    parser.add_argument("-t", "--threads", type=int, default=100, 
                        help="Number of concurrent threads. Default is 100.")
    parser.add_argument("--timeout", type=float, default=1.0, 
                        help="Socket timeout in seconds. Default is 1.0.")
    parser.add_argument("-b", "--banner", action="store_true", 
                        help="Attempt to grab banners from open ports.")
    parser.add_argument("-o", "--output", choices=['json', 'csv'], 
                        help="Output format to save open ports report.")
    parser.add_argument("--no-color", action="store_true", 
                        help="Disable colored output.")
    
    args = parser.parse_args()
    
    if args.no_color:
        Config.COLORS_ENABLED = False

    global logger
    logger = setup_logging()

    print_banner()

    log_msg(f"{colorize('[*]', Colors.OKBLUE)} Target Host: {args.host}")
    
    target_ip = resolve_host(args.host)
    if not target_ip:
        log_msg(f"{colorize('[-]', Colors.FAIL)} Scan aborted. Unresolvable host.", level='error')
        return
        
    ports_to_scan = parse_ports(args.ports)
    if not ports_to_scan:
        log_msg(f"{colorize('[-]', Colors.FAIL)} Scan aborted. No valid ports specified.", level='error')
        return
        
    log_msg(f"{colorize('[*]', Colors.OKBLUE)} Target IP:   {target_ip}")
    log_msg(f"{colorize('[*]', Colors.OKBLUE)} Scan Time:   {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
    log_msg(f"{colorize('[*]', Colors.OKBLUE)} Scanning {len(ports_to_scan)} ports with {args.threads} threads...")
    print("-" * 70)
    
    all_results = []
    open_ports_count = 0
    closed_ports_count = 0
    filtered_ports_count = 0
    error_count = 0
    
    start_time = time.time()
    
    try:
        with concurrent.futures.ThreadPoolExecutor(max_workers=args.threads) as executor:
            futures = {executor.submit(scan_port, target_ip, port, args.timeout, args.banner): port 
                       for port in ports_to_scan}
            
            for future in concurrent.futures.as_completed(futures):
                try:
                    result = future.result()
                    all_results.append(result)
                    
                    if result['status'] == 'open':
                        open_ports_count += 1
                    elif result['status'] == 'closed':
                        closed_ports_count += 1
                    elif result['status'] == 'filtered':
                        filtered_ports_count += 1
                    else:
                        error_count += 1
                        
                except Exception:
                    error_count += 1
                    
    except KeyboardInterrupt:
        log_msg(f"\n{colorize('[!]', Colors.WARNING)} Scan interrupted by user. Shutting down threads...", level='warning')
        executor.shutdown(wait=False, cancel_futures=True)
        return
        
    duration = time.time() - start_time
    all_results.sort(key=lambda x: x['port'])
    
    print("-" * 70)
    log_msg(f"{colorize('[*]', Colors.OKBLUE)} Scan Completed in {duration:.2f} seconds")
    log_msg(f"{colorize('[*]', Colors.OKBLUE)} Summary:")
    log_msg(f"    Total Scanned : {len(ports_to_scan)}")
    log_msg(f"    Open          : {colorize(str(open_ports_count), Colors.OKGREEN if open_ports_count > 0 else Colors.ENDC)}")
    log_msg(f"    Closed        : {closed_ports_count}")
    log_msg(f"    Filtered      : {filtered_ports_count}")
    
    if args.output and open_ports_count > 0:
        save_results(all_results, target_ip, args.host, args.output)

if __name__ == '__main__':
    main()
