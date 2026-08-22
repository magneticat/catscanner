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

Before scanning for changes, generate an initial integrity file. The integrity file is written atomically (via a temporary file then rename), so a crash during generation will not corrupt the existing baseline.

```bash
./catscanner -r -ext ".php,.html,.js" -config config.json
```

On success you'll see: `Integrity file regenerated (N files).`

### Scan for Changes

To check for file modifications:

```bash
./catscanner -s -ext ".php,.html,.js" -config config.json
```

When changes are detected, the program prints a summary such as: `Changes detected: 2 modified, 1 new, 1 whitelisted.` Details are always written to the log file.

### Command Line Options

| Flag | Description |
|------|-------------|
| `-r` | Regenerate the integrity file |
| `-s` | Scan for changes |
| `-ext` | Comma-separated list of file extensions to scan (default: `.php`). Matching is case-insensitive (`.php` includes `example.PHP`). Extensions may omit the leading dot (e.g. `php` becomes `.php`) and are de-duplicated after lowercasing. Empty or invalid (e.g. only commas/spaces, or a path fragment) causes exit 2. |
| `-config` | Path to configuration file (default: `config.json`) |
| `-version` | Print program version and exit |

> **Note:** `-r` and `-s` are mutually exclusive. Use one at a time.

### Exit Codes

| Code | Meaning |
|------|---------|
| `0` | Success: no changes detected (scan) or integrity file regenerated (regen). |
| `1` | Changes detected (scan mode only). |
| `2` | Error: invalid usage (`-s` and `-r` both/neither), config/load failure, invalid or empty `-ext`, regeneration failure, missing integrity file, or scan failure. |

This makes catscanner easy to compose in shell scripts and CI pipelines.

### Version

```bash
./catscanner -version
```

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
    "exclude_dirs": [
        "internal_data/attachments",
        "internal_data/code_cache",
        "internal_data/temp"
    ],
    "whitelist": [
        "*.tmp",
        "cache/*",
        "/path/to/your/web/files/temp/*",
        "test.php"
    ]
}
```

`exclude_dirs` is optional. If it is omitted, behavior matches earlier versions: every matching file under `target_dir` is traversed.

### Configuration Options

| Option | Description |
|--------|-------------|
| `target_dir` | Directory to monitor for changes |
| `integrity_file` | File to store file hashes |
| `log_file` | File to store scan logs |
| `email` | Email address for notifications (To) |
| `from_email` | Optional explicit From address for notifications |
| `email_method` | Email method (`"smtp"` or `"mailcmd"`) |
| `smtp_*` | SMTP server configuration |
| `exclude_dirs` | Optional target-relative directories to skip entirely during traversal |
| `whitelist` | Array of patterns that still get scanned and logged, but do not send notifications |

### Directory exclusions vs whitelist

These settings solve different problems. Do not treat them as interchangeable.

| | `exclude_dirs` | `whitelist` |
|---|---|---|
| Purpose | Skip bulky or high-churn directories so they are never walked | Suppress notifications for files you still want monitored |
| Traversal | The directory and everything beneath it is pruned with `filepath.SkipDir` | Matching files are still hashed and compared |
| Baseline | Excluded paths are omitted from a new baseline, and ignored when reading an older one | Whitelisted files remain in the baseline |
| I/O | Reduces disk reads (useful for attachment, cache, and temp trees) | No I/O savings |
| Alerts | Changes inside an excluded tree produce no log line and no email | Changes are logged as whitelisted; email is skipped |
| Matching | Exact directory paths relative to `target_dir` (no globstar) | `filepath.Match` patterns against name, full path, and trailing sub-paths |

Example for a XenForo-style tree (as used by sites such as Practical Machinist):

```json
"exclude_dirs": [
    "internal_data/attachments",
    "internal_data/code_cache",
    "internal_data/temp"
]
```

Rules for `exclude_dirs`:

- Paths are relative to `target_dir`. Forward slashes are accepted on every OS.
- Empty entries, `.`, absolute paths, and any path that escapes `target_dir` via `..` are rejected (exit 2).
- Adding an exclusion later does **not** report previously baselined files under it as missing.
- Removing an exclusion makes those files appear as **new** until you regenerate the baseline (`-r`).

### Whitelist Patterns

The whitelist lets you keep scanning known-changing files (session files, a specific script) while skipping email alerts. Changes to whitelisted files are still logged. Patterns use Go's `filepath.Match` syntax and are matched against the filename, full path, and every trailing sub-path:

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

Go unit and CLI tests live in `integrity_test.go` and assert exit codes plus the behaviors above (clean scan, new/modified/deleted files, case-insensitive extensions, exclusions, whitelist, and config errors).

```bash
go test ./...
go vet ./...
```

The shell script (`test_integrity.sh`) is a self-contained integration test — it creates a temporary directory, asserts each scenario, and cleans up after itself. No configuration needed.

```bash
chmod +x test_integrity.sh
./test_integrity.sh
```

### Operational Runbook

| Scenario | Action |
|----------|--------|
| First deployment | Run `./catscanner -r -ext ".php,.html,.js" -config config.json` to create the initial integrity baseline. |
| Legitimate file changes | After deploying updates, run `-r` again to refresh the baseline. |
| Scan fails with "Failed to read integrity file" (or missing file) | Run `-r` to regenerate; the integrity file may be missing or corrupted. |
| Error: "no valid file extensions provided via -ext" | Provide at least one non-empty extension in `-ext` (e.g. `-ext ".php,.html"`). |
| Error loading configuration / `exclude_dirs` rejected | Confirm the JSON is valid, required fields are set, and every `exclude_dirs` entry is a non-empty path relative to `target_dir` (not `.`, not absolute, and not escaping with `..`). Config errors exit 2. |
| No email received | Check `email_method`, SMTP/mailcmd config, and the log file for errors. |
| False positives from cache/temp | If the tree should not be scanned at all, add it to `exclude_dirs`. If you still want it hashed and logged, add a `whitelist` pattern instead. |

## Security Considerations

1. Store the integrity and log files outside the web root
2. Disable write permissions on the integrity file after generation
3. Use a dedicated email account for notifications
4. Keep the config file secure (contains SMTP credentials)
5. Regenerate the integrity file after every legitimate deployment
6. Email headers (From, To, Subject) are sanitized to prevent header injection when using SMTP or the mail command

## Contributing

Contributions are welcome! Please feel free to submit a Pull Request.

## License

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.

## Acknowledgments

- Inspired by the need for a simple, efficient file integrity monitoring solution
- Built with Go's standard library for minimal dependencies
