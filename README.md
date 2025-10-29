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

4. Edit `config.json` to match your environment:
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

- `-r`: Regenerate the integrity file
- `-s`: Scan for changes
- `-ext`: Comma-separated list of file extensions to scan (default: ".php")
- `-config`: Path to configuration file (default: "config.json")

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
  - 587: STARTTLS (what this tool uses with `smtp.SendMail` if supported)
  - 465: Implicit TLS (not supported by `smtp.SendMail`; use 587 instead)
- Many providers require a valid From header that matches the authenticated user. Set `from_email` to your mailbox, or leave it empty to default to `smtp_user`.
- Some providers (e.g., Gmail) require an App Password or OAuth; normal password may fail.
- Make sure DNS for the From domain has proper SPF/DMARC to avoid spam/bounces.
- If using `mailcmd`, verify the local MTA is configured to relay mail externally; otherwise messages may remain local or be rejected.
- Check the application log file for detailed SMTP or mail command error messages.

## Security Considerations

1. Store the integrity and log files outside the web root
2. Disable write permissions on the integrity file after its generation
3. Use a dedicated email account for notifications
4. Keep the config file secure (contains SMTP credentials)
5. Regular updates of the integrity file after legitimate changes

## Contributing

Contributions are welcome! Please feel free to submit a Pull Request.

## License

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.

## Acknowledgments

- Inspired by the need for a simple, efficient file integrity monitoring solution
- Built with Go's standard library for minimal dependencies

## Configuration

Edit the `config.json` file to match your environment:

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
| `target_dir` | Directory to monitor for changes |
| `integrity_file` | File to store file hashes |
| `log_file` | File to store scan logs |
| `email` | Email address for notifications (To) |
| `from_email` | Optional explicit From address for notifications |
| `email_method` | Email method ("smtp" or "mailcmd") |
| `smtp_*` | SMTP server configuration |
| `whitelist` | Array of patterns to exclude from notifications |

### Whitelist Patterns

The whitelist feature allows you to specify files or patterns that should not trigger email notifications when changed. Changes to whitelisted files are still logged but won't generate alerts. Patterns support standard glob syntax:

- `*`: Matches any sequence of characters except path separators
- `?`: Matches any single character except path separator
- `[abc]`: Matches one character given in the bracket
- `**`: Matches zero or more directories

Examples:
```json
"whitelist": [
    "*.tmp",           // Ignore all .tmp files
    "cache/*",         // Ignore everything in the cache directory
    "**/temp/**",      // Ignore files in any temp directory
    "test.php",        // Ignore a specific file
    "/full/path/*"     // Ignore files in a specific directory (full path)
]
```

## SMTP/Mail Troubleshooting

- Ensure your SMTP port matches the server capability:
  - 587: STARTTLS (what this tool uses with `smtp.SendMail` if supported)
  - 465: Implicit TLS (not supported by `smtp.SendMail`; use 587 instead)
- Many providers require a valid From header that matches the authenticated user. Set `from_email` to your mailbox, or leave it empty to default to `smtp_user`.
- Some providers (e.g., Gmail) require an App Password or OAuth; normal password may fail.
- Make sure DNS for the From domain has proper SPF/DMARC to avoid spam/bounces.
- If using `mailcmd`, verify the local MTA is configured to relay mail externally; otherwise messages may remain local or be rejected.
- Check the application log file for detailed SMTP or mail command error messages. 