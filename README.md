# crlf-hunter

**CRLF Injection / HTTP Response Splitting Detection Tool**

A Python 3 CLI tool for authorized penetration testing to detect CRLF injection and HTTP response splitting vulnerabilities in web applications.

## ⚠️ IMPORTANT: AUTHORIZED TESTING ONLY

**This tool is for use ONLY against systems you own or are explicitly authorized to test.**

- Unauthorized testing of third-party systems may violate computer crime laws
- Always obtain written permission before testing any system
- The authors assume no liability for misuse of this tool
- Use responsibly and ethically

## Features

- **Raw socket control** - Uses Python standard library only (socket, ssl) so literal CRLF bytes survive on the wire
- **No external dependencies** - Runs on stock Python 3 (tested on Kali Linux)
- **Multiple injection points** - Query parameters, headers (Referer, User-Agent, X-Forwarded-For, Cookie), and POST body fields
- **7 CRLF payload variants** - Including encoded, double-encoded, and UTF-8 bypasses
- **Response splitting detection** - Detects true HTTP response splitting (multiple status lines)
- **Colored live output** - Real-time PASS/FAIL results in terminal
- **JSON reports** - Full machine-readable output for CI/CD integration
- **Batch mode** - Scan multiple targets from a file

## Installation

```bash
git clone <repository>
cd crlf-hunter
chmod +x install.sh
sudo ./install.sh
```

Or run directly without installing:
```bash
python3 -m crlf_hunter.cli --help
```

## Requirements

- Python 3.6+
- Standard library only (no pip packages needed)

## Usage

### Basic scan (query parameters)
```bash
crlf-hunter -u "https://example.com/search?q=test" --confirm
```

### With header fuzzing
```bash
crlf-hunter -u "https://example.com/" --header-fuzz --confirm
```

### POST body fuzzing
```bash
crlf-hunter -u "https://example.com/login" -X POST --body-fuzz \
  --body-params "username=admin,password=secret" --confirm
```

### Batch scan from file
```bash
crlf-hunter -l targets.txt --header-fuzz --confirm
```

### Save JSON report
```bash
crlf-hunter -u "https://example.com/" -o report.json --confirm
```

### Verbose mode (show raw requests/responses)
```bash
crlf-hunter -u "https://example.com/" -v --confirm
```

## CLI Options

| Flag | Description |
|------|-------------|
| `-u, --url` | Target URL (required unless `-l` used) |
| `-l, --list` | Path to file of target URLs, one per line |
| `-p, --params` | Comma-separated param names to fuzz (default: auto-detect) |
| `--header-fuzz` | Also inject into Referer, User-Agent, X-Forwarded-For, Cookie |
| `--body-fuzz` | Also inject into POST body fields (requires `-X POST`) |
| `-X` | HTTP method (default: GET) |
| `--body-params` | Body params for POST, e.g., `user=admin,pass=secret` |
| `-d, --delay` | Delay between requests in seconds (default: 0.5) |
| `-t, --timeout` | Socket timeout in seconds (default: 10) |
| `-o, --output` | Output report file path (.json) |
| `-v, --verbose` | Print raw request/response for every test case |
| `--confirm` | **Required** - confirm authorization before testing |

## Payloads Tested

The tool tests 7 CRLF injection payload variants, each combined with a unique marker (`crlfhunter_poc`):

1. `%0d%0aSet-Cookie:{marker}=1` - Standard URL-encoded CRLF
2. `%0D%0ASet-Cookie:{marker}=1` - Uppercase encoding
3. `\r\nSet-Cookie:{marker}=1` - Literal CRLF
4. `%0d%0a%0d%0a{marker}-BODY-SPLIT` - Double CRLF for body splitting
5. `%E5%98%8A%E5%98%8DSet-Cookie:{marker}=1` - UTF-8 encoded CRLF
6. `%250d%250aSet-Cookie:{marker}=1` - Double-encoded CRLF
7. `%0d%0aLocation:https://evil.example/{marker}` - Location header injection

## Detection Logic

A target is flagged **VULNERABLE** if:

1. **Marker in response headers** - The marker appears as a parsed HTTP header name or value
2. **Marker in Set-Cookie** - The marker appears in a Set-Cookie header (injected cookie)
3. **Response splitting** - Two distinct `HTTP/1.x` status lines found in one response

**NOT vulnerable** (reflection only):
- Marker appears only in HTML body content (different bug class)

## Example Output

```
╔══════════════════════════════════════════════════════════════╗
║                    crlf-hunter v1.0.0                        ║
║         CRLF Injection / HTTP Response Splitting Scanner     ║
║                    FOR AUTHORIZED TESTING ONLY               ║
╚══════════════════════════════════════════════════════════════╝

⚠  AUTHORIZATION REQUIRED
Type the target hostname to confirm you are authorized to test it:
  Target: example.com
> example.com
Authorization confirmed.

Target: https://example.com/search?q=test
Method: GET
Host: example.com:443 (https)
Path: /search
Query params: ['q']
Header fuzz: Disabled
Body fuzz: Disabled
Delay: 0.5s
Timeout: 10s

Total test cases: 7

[1/7] query:q                       [SAFE]
[2/7] query:q                       [SAFE]
[3/7] query:q                       [VULNERABLE] -> set-cookie: crlfhunter_poc=1
[4/7] query:q                       [SAFE]
[5/7] query:q                       [SAFE]
[6/7] query:q                       [SAFE]
[7/7] query:q                       [SAFE]

============================================================
SCAN COMPLETE: 1 VULNERABLE out of 7 tests
============================================================

JSON report written to: report.json
```

## JSON Report Format

```json
{
  "tool": "crlf-hunter",
  "version": "1.0.0",
  "timestamp": "2024-01-15T10:30:00Z",
  "target": "https://example.com/search?q=test",
  "config": {
    "method": "GET",
    "header_fuzz": false,
    "body_fuzz": false,
    "delay": 0.5,
    "timeout": 10
  },
  "summary": {
    "total_tests": 7,
    "vulnerable": 1,
    "safe": 6
  },
  "results": [
    {
      "url": "https://example.com/search?q=test",
      "injection_point": {
        "type": "query",
        "name": "q",
        "original_value": "test"
      },
      "payload": "%0d%0aSet-Cookie:crlfhunter_poc=1",
      "vulnerable": true,
      "evidence": "set-cookie: crlfhunter_poc=1",
      "raw_snippet": "HTTP/1.1 200 OK\r\nSet-Cookie: crlfhunter_poc=1\r\n...",
      "detection_type": "marker_in_set_cookie"
    }
  ]
}
```

## Exit Codes

- `0` - No vulnerabilities found
- `1` - Vulnerabilities detected
- `130` - Interrupted by user (Ctrl+C)

## Project Structure

```
crlf-hunter/
├── crlf_hunter/
│   ├── __init__.py
│   ├── cli.py          # argparse entrypoint
│   ├── payloads.py     # CRLF injection payloads
│   ├── targets.py      # URL parsing
│   ├── injector.py     # Raw HTTP request building
│   ├── sender.py       # Raw socket send/receive
│   ├── analyzer.py     # Response analysis
│   └── report.py       # Colored output & JSON
├── install.sh          # Symlink installer
├── README.md           # This file
└── setup.py            # Package metadata
```

## License

This tool is provided for authorized security testing only. See LICENSE file for details.

## Disclaimer

The authors are not responsible for any misuse or damage caused by this tool. Always ensure you have explicit written authorization before testing any system.