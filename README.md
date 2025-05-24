# Advanced Path Traversal Scanner

A professional tool for detecting path traversal vulnerabilities in web applications. This scanner systematically tests for directory traversal issues by attempting to access files outside the web application's intended directory structure.

## Features

- **Advanced Traversal Techniques**: Tests multiple traversal methods including:
  - Standard `../` traversal
  - URL-encoded `%2e%2e%2f`
  - Double URL-encoded `%252e%252e%252f`
  - Mixed encoding `..%2f`
  - Path normalization bypass
- **Multi-threaded Scanning**: Uses concurrent.futures for efficient testing
- **Target Validation**: Automatically checks target URL accessibility before scanning
- **404 Handling**: Can optionally ignore 404 errors with --ignore-404 flag
- **Response Analysis**: 
  - Status code monitoring
  - Content length tracking
  - Response time measurement
  - Header analysis
  - Content preview with first 200 characters
- **Flexible Configuration**: 
  - Customizable traversal depth
  - Adjustable thread count
  - Proxy support
  - Custom headers and cookies
  - User-agent customization
- **Security Features**: 
  - SSL certificate validation (optional)
  - Input validation
  - Request timeout handling
  - Error logging and debugging

## Requirements

- Python 3.6+
- Required packages:
  - requests
  - rich

## Installation

```bash
# Clone the repository or download the script
git clone https://github.com/yourusername/path-traversal.git
cd path-traversal

# Install required packages
pip install requests rich
```

## Usage

Basic usage:

```bash
python checker.py -u "http://example.com" -p "file"
```

Advanced usage:

```bash
python checker.py -u "http://example.com" -e "download" -p "file" -d 10 --threads 10 --output results.txt --verbose
```

### Command Line Arguments

| Option | Long Option | Description | Default |
|--------|-------------|-------------|----------|
| `-u` | `--url` | Target URL (required) | - |
| `-e` | `--endpoint` | Endpoint to test (default: none) | - |
| `-p` | `--parameter` | Query parameter name (required) | - |
| `-d` | `--depth` | Maximum directory traversal depth | 10 |
| `-t` | `--timeout` | Request timeout in seconds | 5.0 |
| `-o` | `--output` | Output file for results | - |
| `-v` | `--verbose` | Enable verbose output | - |
| `--threads` | | Number of concurrent threads | 10 |
| `--proxy` | | Proxy to use (e.g., http://127.0.0.1:8080) | --- |
| `--user-agent` | | Custom User-Agent header | Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36 |
| `--cookies` | | Cookies to include with requests (format: name1=value1; name2=value2) | - |
| `--insecure` | | Disable SSL certificate verification | - |
| `--files` | | Comma-separated list of files to test | - |
| `--ignore-404` | | Continue scanning even if target URL returns 404 | - |

## Examples

Test for path traversal in a file parameter:
```bash
python checker.py -u "http://example.com" -p "file"
```

Test with specific endpoint:
```bash
python checker.py -u "http://example.com" -e "download" -p "ticket"
```

Test with authentication cookies:
```bash
python checker.py -u "http://example.com" -p "file" --cookies "session=abc123; auth=xyz789"
```

Test through a proxy:
```bash
python checker.py -u "http://example.com" -p "file" --proxy "http://127.0.0.1:8080"
```

Test specific files:
```bash
python checker.py -u "http://example.com" -p "file" --files "/etc/passwd,wp-config.php,config.php"
```

## Ethical Usage

This tool is intended for:
- Security professionals conducting authorized penetration tests
- System administrators testing their own systems
- Developers checking for vulnerabilities in their code

**Always obtain proper authorization before testing any system you don't own.**

## License

[MIT License](LICENSE)
