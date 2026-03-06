# MagnetiCat Simple Integrity Scanner (catscanner)

A lightweight, efficient file integrity monitoring tool written in Go. This tool helps system administrators and website owners monitor web files for unauthorized changes, which could indicate a security breach or malware infection.

Repository: [magneticat/catscanner](https://github.com/magneticat/catscanner.git)

## Features

- 🔒 **File Integrity Monitoring**: Generates and verifies SHA-256 hashes of files
- 🔍 **Change Detection**: Identifies new, modified, and deleted files
- 📧 **Notifications**: Email alerts when changes are detected
- 📝 **Detailed Logging**: All activities are logged with timestamps
- ⚙️ **Flexible Configuration**: JSON-based configuration file
- 🔄 **Multiple File Types**: Support for monitoring various file extensions
- 📨 **Email Options**: Supports both SMTP and local mail command

## Quick Start

### Prerequisites

- Go 1.16 or higher
- For mail command notifications: `mailutils` (Debian/Ubuntu) or `mailx` (CentOS/RHEL)

### Installation

1. Clone the repository:
   ```bash
   git clone https://github.com/magneticat/catscanner.git
   cd catscanner
   ```

2. Build the binary:
   ```bash
   go build -o catscanner
   ```

3. Create your configuration:
   ```bash
   cp config.example.json config.json
   ```

4. Edit `config.json` to match your environment (see [Configuration](#configuration) below).

## Usage

### Generate Initial Integrity File

Before scanning for changes, generate an initial integrity file:

```bash
./catscanner -r -ext ".php,.html,.js"
```

### Scan for Changes

To check for file modifications:

```bash
./catscanner -s -ext ".php,.html,.js"
```

### Command Line Options

| Flag | Description |
|------|-------------|
| `-r` | Regenerate the integrity file |
| `-s` | Scan for changes |
| `-ext` | Comma-separated list of file extensions to scan (default: `.php`) |
| `-config` | Path to configuration file (default: `config.json`) |

> **Note:** `-r` and `-s` are mutually exclusive. Use one at a time.

### Exit Codes

When running in scan mode (`-s`), the binary exits with:

| Code | Meaning |
|------|---------|
| `0` | No changes detected |
| `1` | Changes detected |
| `2` | Error (missing integrity file, scan failure, etc.) |

This makes catscanner easy to compose in shell scripts and CI pipelines.

## Configuration

Edit `config.json` to match your environment:

```json
{
    "target_dir": "/path/to/your/web/files",
    "integrity_file": "/path/to/logs/integrity.txt",
    "log_file": "/path/to/logs/integrity.log",
    "email": "your_email@example.com",
    "from_email": "alerts@example.com",
    "email_method": "mailcmd",
    "smtp_server": "smtp.example.com",
    "smtp_port": "587",
    "smtp_user": "smtp_username",
    "smtp_pass": "smtp_password",
    "whitelist": [
        "*.tmp",
        "cache/*",
        "/path/to/your/web/files/temp/*",
        "test.php"
    ]
}
```

### Configuration Options

| Option | Description |
|--------|-------------|
| `target_dir` | **Required.** Directory to monitor for changes |
| `integrity_file` | **Required.** File to store file hashes |
| `log_file` | **Required.** File to store scan logs |
| `email` | Email address for notifications (To). Optional if no notifications needed. |
| `from_email` | Optional explicit From address for notifications |
| `email_method` | Email method (`"smtp"` or `"mailcmd"`). If empty or invalid, scans run but no notifications are sent. |
| `smtp_*` | SMTP server configuration (required when `email_method` is `"smtp"`) |
| `whitelist` | Array of patterns to exclude from notifications (optional) |

### Whitelist Patterns

The whitelist lets you exclude known-changing files (caches, temp files) from triggering alerts. Changes to whitelisted files are still logged but won't generate email notifications. Patterns use Go's `filepath.Match` syntax and are matched against the filename, full path, and every trailing sub-path:

- `*` — any sequence of characters except path separators
- `?` — any single character except path separator
- `[abc]` — one character in the bracket set

> **Note:** `**` (globstar) is not supported.

Examples:
```json
"whitelist": [
    "*.tmp",                         // Ignore all .tmp files
    "cache/*",                       // Ignore everything inside a cache/ directory
    "test.php",                      // Ignore a specific file by name
    "/full/path/to/specific/file"    // Ignore one file by absolute path
]
```

### Integrity File Format

The integrity file stores one line per monitored file: `SHA256_HASH  /full/path/to/file` (two spaces between hash and path). The format is compatible with `sha256sum -c` for manual verification.

## Email Notification Methods

### 1. Local Mail Command

The simplest option for Linux/Unix systems. Requires a local mail transport agent.

```json
{
    "email_method": "mailcmd",
    "email": "your_email@example.com"
}
```

Install required packages:
```bash
# Debian/Ubuntu
sudo apt-get install mailutils

# CentOS/RHEL
sudo yum install mailx
```

### 2. SMTP Server

For using an external SMTP server:

```json
{
    "email_method": "smtp",
    "email": "your_email@example.com",
    "smtp_server": "smtp.example.com",
    "smtp_port": "587",
    "smtp_user": "username",
    "smtp_pass": "password"
}
```

## Setting Up as a Cron Job

For regular monitoring, add to crontab:

```bash
# Check every hour
0 * * * * /path/to/catscanner -s -ext ".php,.html,.js" -config /path/to/config.json
```

## SMTP/Mail Troubleshooting

- Ensure your SMTP port matches the server capability:
  - 587: STARTTLS (recommended, used by `smtp.SendMail`)
  - 465: Implicit TLS (not supported; use 587 instead)
- Many providers require a valid From header that matches the authenticated user. Set `from_email` to your mailbox, or leave it empty to default to `smtp_user`.
- Some providers (e.g., Gmail) require an App Password or OAuth; a normal password may fail.
- Make sure the From domain has proper SPF/DMARC records to avoid spam filtering.
- If using `mailcmd`, verify the local MTA is configured to relay mail externally.
- Check the application log file for detailed SMTP or mail command error messages.

## Development and Testing

### Running Tests

The test script (`test_integrity.sh`) demonstrates the full workflow and is fully self-contained — it creates a temporary directory, runs all scenarios, and cleans up after itself. No configuration needed.

```bash
chmod +x test_integrity.sh
./test_integrity.sh
```

The script: builds the binary, regenerates the integrity file, scans (no changes), creates a test file, scans again (detects new file), removes the test file, scans again (returns to baseline; no changes), then prints the log and cleans up. It uses a generated config with empty email settings, so no notifications are sent.

### Operational Runbook

| Scenario | Action |
|----------|--------|
| First deployment | Run `./catscanner -r -ext ".php,.html,.js"` to create the initial integrity baseline. |
| Legitimate file changes | After deploying updates, run `-r` again to refresh the baseline. |
| Scan fails with "Failed to read integrity file" | Run `-r` to regenerate; the integrity file may be missing or corrupted. |
| No email received | Check `email_method`, SMTP/mailcmd config, and the log file for errors. |
| False positives from cache/temp | Add patterns to `whitelist` in `config.json`. |

## Security Considerations

1. Store the integrity and log files outside the web root
2. Disable write permissions on the integrity file after generation (e.g. `chmod 444 /path/to/integrity.txt`)
3. Use a dedicated email account for notifications
4. Keep the config file secure (contains SMTP credentials)
5. Regenerate the integrity file after every legitimate deployment

## Contributing

Contributions are welcome! Please feel free to submit a Pull Request.

## License

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.

## Acknowledgments

- Inspired by the need for a simple, efficient file integrity monitoring solution
- Built with Go's standard library for minimal dependencies