# Advanced TCP Port Scanner

A fast, concurrent, and uniquely designed TCP Port Scanner built with Python for an internship project.

## Advanced Features
- **Striking UI:** Includes a cool ASCII banner and elegant, terminal-friendly colored output.
- **Service Resolution:** Automatically resolves port numbers to their common service names (e.g., `80 -> http`).
- **Banner Grabbing:** Uses the `-b` flag to intelligently grab the service banner details (e.g. attempting to read HTTP headers or SSH banners).
- **Latency Tracking:** Measures and outputs the connection latency for each discovered open port.
- **Export Formats:** Supports exporting your cleanly formatted findings to both JSON and CSV files automatically using the `-o` flag.
- **Concurrency Setup:** Uses `concurrent.futures.ThreadPoolExecutor` for high-speed port scanning.
- **Flexibility:** Scanning options for hostname resolution, custom multiple ranges, timeouts, and threads.
- **Log Sanitation:** Maintains a beautifully colorized standard output while keeping file logs appropriately stripped of ANSI escape codes.

## Prerequisites
- Python 3.x (Built mostly with standard libraries)

## Usage

Run the scanner via the command prompt/terminal:

```bash
python port_scanner.py <host> [options]
```

### Positional Arguments:
- `host`: The target hostname or IP address to scan (e.g., `google.com` or `127.0.0.1`).

### Optional Arguments:
- `-p`, `--ports`: Ports to scan. Accepts single port, comma-separated list, or ranges. Default is `1-1024`.
  - Example: `80`, `22,80,443`, or `1-65535`
- `-t`, `--threads`: Number of concurrent threads to use. Default is `100`. Increase for super-fast scans.
- `--timeout`: Socket connection timeout in seconds. Default is `1.0`. 
- `-b`, `--banner`: Enable Banner Grabbing on open ports.
- `-o`, `--output {json,csv}`: Specify an export format to save results into a standalone file.
- `--no-color`: Disable standard terminal colored text (useful for environments without ANSI support).

## Cool Examples

**The "Ultimate" Scan (Banner Grabbing & CSV Export):**
```bash
python port_scanner.py scanme.nmap.org -p 22,80,443,3306 -b -o csv
```

**Heavy Multi-threaded Rapid Scan:**
```bash
python port_scanner.py localhost -p 1-10000 -t 500 --timeout 0.3
```

**Export as Clean JSON:**
```bash
python port_scanner.py 10.0.0.5 -p 1-1024 -o json
```

## Logging
Every execution runs safely and automatically creates a persistent execution context logic into `port_scanner.log` in your current directory. It is specially designed to clean the logging streams so you only print raw text into your history without weird formatting characters!
