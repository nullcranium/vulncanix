# Vulncanix - Web Vulnerability Scanner

```
 ██╗   ██╗██╗   ██╗██╗     ███╗   ██╗ ██████╗ █████╗ ███╗   ██╗██╗██╗  ██╗
 ██║   ██║██║   ██║██║     ████╗  ██║██╔════╝██╔══██╗████╗  ██║██║╚██╗██╔╝
 ██║   ██║██║   ██║██║     ██╔██╗ ██║██║     ███████║██╔██╗ ██║██║ ╚███╔╝ 
 ╚██╗ ██╔╝██║   ██║██║     ██║╚██╗██║██║     ██╔══██║██║╚██╗██║██║ ██╔██╗ 
  ╚████╔╝ ╚██████╔╝███████╗██║ ╚████║╚██████╗██║  ██║██║ ╚████║██║██╔╝ ██╗
   ╚═══╝   ╚═════╝ ╚══════╝╚═╝  ╚═══╝ ╚═════╝╚═╝  ╚═╝╚═╝  ╚═══╝╚═╝╚═╝  ╚═╝
```

A professional, fast, and concurrent web vulnerability scanner written in Rust with a modern colorful interface. Features intelligent directory enumeration, smart crawling, and parameter discovery to uncover hidden resources in web applications.

## Installation

### Prerequisites

- Rust (latest stable version)
- Cargo package manager

### Build from Source

```bash
git clone https://github.com/nullcranium/vulncanix
cd vulncanix
cargo build --release
```

The binary will be available at `target/release/vulncanix`

## Usage

### Basic Usage

```bash
vulncanix -t https://example.com
```

### Advanced Usage

```bash
vulncanix -t https://example.com \
  -w /path/to/wordlist.txt \
  -c 50 \
  -T 15 \
  -e php,html,js \
  -o json \
  --status-codes 200,301,403 \
  --follow-redirects \
  -k \
  -v
```

## Command Line Options

| Option | Short | Description | Default |
|--------|--------|-------------|---------|
| `--target` | `-t` | Target URL to scan | **Required** |
| `--concurrency` | `-c` | Number of concurrent requests | `10` |
| `--timeout` | `-T` | Request timeout in seconds | `10` |
| `--wordlist` | `-w` | Path to wordlist file or URL | `https://raw.githubusercontent.com/Bo0oM/fuzz.txt/master/fuzz.txt` |
| `--output` | `-o` | Output format (txt, json) | `txt` |
| `--extensions` | `-e` | File extensions to append (comma-separated) | None |
| `--status-codes` | | Show only specific status codes (comma-separated) | All interesting codes |
| `--hide-status-codes` | | Hide specific status codes (comma-separated) | None |
| `--user-agent` | | Custom User-Agent string | `vulncanix/1.0` |
| `--follow-redirects` | | Follow HTTP redirects | `false` |
| `--verbose` | `-v` | Verbose output | `false` |
| `--insecure` | `-k` | Skip SSL certificate verification (insecure) | `false` |
| `--crawl` | | Enable crawler mode | `false` |
| `--depth` | | Max crawl depth | `3` |
| `--max-pages` | | Max pages to crawl | `100` |
| `--allow-external` | | Allow crawling external domains | `false` |
| `--hybrid` | | Enable hybrid mode (crawler + wordlist scanning) | `false` |
| `--bar` | | Show progress bar during scanning | `false` |


## Examples

### Basic Directory Enumeration

```bash
# Scan with default settings
vulncanix -t https://example.com

# Use custom wordlist
vulncanix -t https://example.com -w /usr/share/wordlists/dirb/common.txt
```

### High-Performance Scanning

```bash
# High concurrency scan
vulncanix -t https://example.com -c 100 -T 5

# Fast scan with specific extensions
vulncanix -t https://example.com -c 50 -e php,html,js,txt
```

### SSL Certificate Handling

```bash
# Skip SSL certificate verification for self-signed or invalid certificates
vulncanix -t https://example.com -k
```

### Filtered Results

```bash
# Show only successful responses
vulncanix -t https://example.com --status-codes 200,301

# Hide 404 and 403 responses
vulncanix -t https://example.com --hide-status-codes 404,403
```

### Output Options

```bash
# JSON output for automation
vulncanix -t https://example.com -o json > results.json

# Verbose mode for debugging
vulncanix -t https://example.com -v
```

### Using Remote Wordlists

```bash
# Use a wordlist from GitHub
vulncanix -t https://example.com -w https://raw.githubusercontent.com/danielmiessler/SecLists/master/Discovery/Web-Content/directory-list-2.3-medium.txt
```

### Smart Crawler

Vulncanix includes a heuristic smart crawler that can discover and prioritize URLs based on their potential for vulnerabilities.

```bash
# Start crawler with default settings
vulncanix -t https://example.com --crawl

# Configure crawl depth and max pages
vulncanix -t https://example.com --crawl --depth 3 --max-pages 200

# Allow crawling external domains
vulncanix -t https://example.com --crawl --allow-external
```

### Hybrid Scanning Mode

Hybrid mode combines the best of both worlds: dynamic URL discovery via crawling followed by comprehensive wordlist-based fuzzing on discovered endpoints.

```bash
# Basic hybrid scan - crawl then fuzz discovered paths
vulncanix -t https://example.com --crawl --hybrid

# Hybrid scan with custom settings
vulncanix -t https://example.com --crawl --hybrid \
  --depth 3 \
  --max-pages 200 \
  -c 50 \
  -w /path/to/wordlist.txt

# Aggressive hybrid scan with extensions
vulncanix -t https://example.com --crawl --hybrid \
  --depth 5 \
  --max-pages 500 \
  -e php,html,js,txt,bak \
  -c 100
```


## Disclaimer

This tool is for educational and authorized security testing purposes only. Always ensure you have explicit permission before scanning any target. The authors are not responsible for any misuse of this tool.