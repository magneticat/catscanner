package main

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"log"
	"net/smtp"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"time"
)

// Configuration structure
type Config struct {
	TargetDir     string   `json:"target_dir"`
	IntegrityFile string   `json:"integrity_file"`
	LogFile       string   `json:"log_file"`
	Email         string   `json:"email"`
	Whitelist     []string `json:"whitelist"` // Patterns to ignore for notifications

	// Optional explicit From address for notifications
	FromEmail string `json:"from_email"`

	// SMTP configuration
	SmtpServer string `json:"smtp_server"`
	SmtpPort   string `json:"smtp_port"`
	SmtpUser   string `json:"smtp_user"`
	SmtpPass   string `json:"smtp_pass"`

	// Email notification method: "smtp" or "mailcmd"
	EmailMethod string `json:"email_method"`
}

// Global configuration variable
var config Config

func loadConfig(configPath string) error {
	// Set default config file path if not provided
	if configPath == "" {
		configPath = "config.json"
	}

	// Read config file
	data, err := os.ReadFile(configPath)
	if err != nil {
		return fmt.Errorf("failed to read config file: %w", err)
	}

	// Parse JSON
	err = json.Unmarshal(data, &config)
	if err != nil {
		return fmt.Errorf("failed to parse config file: %w", err)
	}

	return nil
}

func main() {
	// Define command line flags.
	scanMode := flag.Bool("s", false, "Scan for file changes")
	regenMode := flag.Bool("r", false, "Regenerate the integrity file")
	extFlag := flag.String("ext", ".php", "Comma-separated list of file extensions to scan (e.g., .php,.html)")
	configFlag := flag.String("config", "config.json", "Path to configuration file")
	flag.Parse()

	// Load configuration
	err := loadConfig(*configFlag)
	if err != nil {
		log.Fatalf("Error loading configuration: %v", err)
	}

	// At least one flag must be specified.
	if !*scanMode && !*regenMode {
		fmt.Println("Usage: integrity -s (scan) or -r (regenerate integrity file) [-ext \".php,.html\"] [-config path/to/config.json]")
		os.Exit(1)
	}

	// Parse extensions into a slice.
	extensions := parseExtensions(*extFlag)

	if *regenMode {
		regenerateIntegrity(extensions)
	}

	if *scanMode {
		scanFiles(extensions)
	}
}

// parseExtensions converts the comma-separated list of extensions into a slice,
// ensuring each extension starts with a dot.
func parseExtensions(extStr string) []string {
	rawExts := strings.Split(extStr, ",")
	var exts []string
	for _, ext := range rawExts {
		trimmed := strings.TrimSpace(ext)
		if !strings.HasPrefix(trimmed, ".") {
			trimmed = "." + trimmed
		}
		exts = append(exts, trimmed)
	}
	return exts
}

// regenerateIntegrity walks through TARGET_DIR, computes SHA-256 hashes for files
// matching the provided extensions, and writes the hash and file path to the integrity file.
func regenerateIntegrity(extensions []string) {
	file, err := os.Create(config.IntegrityFile)
	if err != nil {
		log.Fatalf("Failed to create integrity file: %v", err)
	}
	defer file.Close()

	err = filepath.Walk(config.TargetDir, func(path string, info os.FileInfo, err error) error {
		if err != nil {
			return err
		}
		if !info.IsDir() && hasValidExtension(info.Name(), extensions) {
			hash, err := computeHash(path)
			if err != nil {
				return err
			}
			fmt.Fprintf(file, "%s  %s\n", hash, path)
		}
		return nil
	})
	if err != nil {
		log.Fatalf("Error during integrity file generation: %v", err)
	}
	appendLog("Integrity file regenerated.")
	fmt.Println("Integrity file regenerated.")
}

// isWhitelisted checks if a file path matches any whitelist pattern
func isWhitelisted(path string, whitelist []string) bool {
	for _, pattern := range whitelist {
		matched, err := filepath.Match(pattern, filepath.Base(path))
		if err == nil && matched {
			return true
		}
		// Also try matching the full path
		matched, err = filepath.Match(pattern, path)
		if err == nil && matched {
			return true
		}
	}
	return false
}

// scanFiles loads the stored integrity file, rescans files in TARGET_DIR that match the provided extensions,
// compares the computed hashes with the stored values, logs discrepancies, and sends an email if needed.
func scanFiles(extensions []string) {
	// Load stored integrity data.
	storedHashes := make(map[string]string)
	content, err := os.ReadFile(config.IntegrityFile)
	if err != nil {
		log.Fatalf("Failed to read integrity file: %v", err)
	}
	lines := strings.Split(string(content), "\n")
	for _, line := range lines {
		if strings.TrimSpace(line) == "" {
			continue
		}
		parts := strings.SplitN(line, "  ", 2)
		if len(parts) != 2 {
			continue
		}
		storedHashes[parts[1]] = parts[0]
	}

	// Scan current files.
	currentHashes := make(map[string]string)
	err = filepath.Walk(config.TargetDir, func(path string, info os.FileInfo, err error) error {
		if err != nil {
			return err
		}
		if !info.IsDir() && hasValidExtension(info.Name(), extensions) {
			hash, err := computeHash(path)
			if err != nil {
				return err
			}
			currentHashes[path] = hash
		}
		return nil
	})
	if err != nil {
		log.Fatalf("Error during scanning: %v", err)
	}

	var diffOutput strings.Builder
	var whitelistedChanges strings.Builder
	hasChanges := false
	hasWhitelistedChanges := false

	// Detect new or modified files.
	for path, currentHash := range currentHashes {
		storedHash, exists := storedHashes[path]
		if !exists {
			if isWhitelisted(path, config.Whitelist) {
				whitelistedChanges.WriteString(fmt.Sprintf("Whitelisted new file: %s\n", path))
				hasWhitelistedChanges = true
			} else {
				diffOutput.WriteString(fmt.Sprintf("New file detected: %s\n", path))
				hasChanges = true
			}
		} else if storedHash != currentHash {
			if isWhitelisted(path, config.Whitelist) {
				whitelistedChanges.WriteString(fmt.Sprintf("Whitelisted modified file: %s\n", path))
				hasWhitelistedChanges = true
			} else {
				diffOutput.WriteString(fmt.Sprintf("Modified file: %s\n", path))
				hasChanges = true
			}
		}
	}

	// Detect files that have been removed.
	for path := range storedHashes {
		if _, exists := currentHashes[path]; !exists {
			if isWhitelisted(path, config.Whitelist) {
				whitelistedChanges.WriteString(fmt.Sprintf("Whitelisted file removed: %s\n", path))
				hasWhitelistedChanges = true
			} else {
				diffOutput.WriteString(fmt.Sprintf("File missing: %s\n", path))
				hasChanges = true
			}
		}
	}

	// Log all changes but only send notifications for non-whitelisted changes
	if !hasChanges && !hasWhitelistedChanges {
		appendLog("No changes detected.")
		fmt.Println("No changes detected.")
	} else {
		var logMsg strings.Builder
		if hasChanges {
			logMsg.WriteString("Discrepancies found:\n" + diffOutput.String())
		}
		if hasWhitelistedChanges {
			if logMsg.Len() > 0 {
				logMsg.WriteString("\n")
			}
			logMsg.WriteString("Whitelisted changes (no notification sent):\n" + whitelistedChanges.String())
		}

		appendLog(logMsg.String())
		fmt.Println("Changes detected. Check log for details.")

		// Only send email notification for non-whitelisted changes
		if hasChanges {
			sendEmail("PHP Integrity Alert", diffOutput.String())
		}
	}
}

// hasValidExtension checks if the filename ends with any of the allowed extensions.
func hasValidExtension(filename string, extensions []string) bool {
	for _, ext := range extensions {
		if strings.HasSuffix(filename, ext) {
			return true
		}
	}
	return false
}

// computeHash calculates the SHA-256 hash for the given file.
func computeHash(filePath string) (string, error) {
	file, err := os.Open(filePath)
	if err != nil {
		return "", err
	}
	defer file.Close()
	hasher := sha256.New()
	if _, err := io.Copy(hasher, file); err != nil {
		return "", err
	}
	return hex.EncodeToString(hasher.Sum(nil)), nil
}

// appendLog writes a message to the log file with a timestamp.
func appendLog(message string) {
	f, err := os.OpenFile(config.LogFile, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0644)
	if err != nil {
		fmt.Printf("Failed to write log: %v\n", err)
		return
	}
	defer f.Close()
	timestamp := time.Now().Format(time.RFC3339)
	f.WriteString(fmt.Sprintf("%s - %s\n", timestamp, message))
}

// sendEmail sends an email notification using the configured method
func sendEmail(subject, body string) {
	switch strings.ToLower(config.EmailMethod) {
	case "smtp":
		sendEmailSmtp(subject, body)
	case "mailcmd":
		sendEmailMailCmd(subject, body)
	default:
		fmt.Printf("Email notification skipped: no valid email method configured\n")
		appendLog("Email notification skipped: no valid email method configured")
	}
}

// sendEmailSmtp sends an email using SMTP
func sendEmailSmtp(subject, body string) {
	if config.SmtpServer == "" || config.SmtpPort == "" {
		fmt.Printf("Email notification skipped: SMTP not configured\n")
		appendLog("Email notification skipped: SMTP not configured")
		return
	}

	from := config.FromEmail
	if strings.TrimSpace(from) == "" {
		from = config.SmtpUser
	}

	auth := smtp.PlainAuth("", config.SmtpUser, config.SmtpPass, config.SmtpServer)

	// Build RFC 5322 headers for better deliverability
	headers := make(map[string]string)
	headers["From"] = from
	headers["To"] = config.Email
	headers["Subject"] = subject
	headers["MIME-Version"] = "1.0"
	headers["Content-Type"] = "text/plain; charset=UTF-8"
	headers["Content-Transfer-Encoding"] = "8bit"
	headers["Date"] = time.Now().Format(time.RFC1123Z)

	var sb strings.Builder
	for k, v := range headers {
		sb.WriteString(k)
		sb.WriteString(": ")
		sb.WriteString(v)
		sb.WriteString("\r\n")
	}
	sb.WriteString("\r\n")
	sb.WriteString(body)
	sb.WriteString("\r\n")

	msg := []byte(sb.String())
	addr := config.SmtpServer + ":" + config.SmtpPort
	recipients := []string{config.Email}
	err := smtp.SendMail(addr, auth, from, recipients, msg)
	if err != nil {
		fmt.Printf("Failed to send email via SMTP: %v\n", err)
		appendLog(fmt.Sprintf("Failed to send email via SMTP: %v", err))
	} else {
		appendLog("Email notification sent via SMTP")
	}
}

// sendEmailMailCmd sends an email using the local mail command
func sendEmailMailCmd(subject, body string) {
	// Check if mail command exists
	_, err := exec.LookPath("mail")
	if err != nil {
		fmt.Printf("Email notification skipped: mail command not found\n")
		appendLog("Email notification skipped: mail command not found")
		return
	}

	args := []string{"-s", subject}
	if strings.TrimSpace(config.FromEmail) != "" {
		// Many mail implementations (mailutils) accept -a to add a header
		args = append(args, "-a", "From: "+config.FromEmail)
	}
	args = append(args, config.Email)

	cmd := exec.Command("mail", args...)
	cmd.Stdin = strings.NewReader(body)

	output, err := cmd.CombinedOutput()
	if err != nil {
		fmt.Printf("Failed to send email via mail command: %v\n%s\n", err, output)
		appendLog(fmt.Sprintf("Failed to send email via mail command: %v", err))
	} else {
		appendLog("Email notification sent via mail command")
	}
}
