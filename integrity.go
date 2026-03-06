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

const version = "1.0.0"

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

	// Validate required fields
	if config.TargetDir == "" {
		return fmt.Errorf("config: target_dir is required")
	}
	if config.IntegrityFile == "" {
		return fmt.Errorf("config: integrity_file is required")
	}
	if config.LogFile == "" {
		return fmt.Errorf("config: log_file is required")
	}

	return nil
}

func main() {
	// Define command line flags.
	scanMode := flag.Bool("s", false, "Scan for file changes")
	regenMode := flag.Bool("r", false, "Regenerate the integrity file")
	extFlag := flag.String("ext", ".php", "Comma-separated list of file extensions to scan (e.g., .php,.html)")
	configFlag := flag.String("config", "config.json", "Path to configuration file")
	versionFlag := flag.Bool("version", false, "Print version and exit")
	flag.Parse()

	if *versionFlag {
		fmt.Printf("catscanner %s\n", version)
		return
	}

	// Load configuration
	err := loadConfig(*configFlag)
	if err != nil {
		log.Fatalf("Error loading configuration: %v", err)
	}

	// Exactly one mode must be specified; both together would scan a freshly-
	// regenerated file and trivially find no changes, which is misleading.
	if *scanMode && *regenMode {
		fmt.Println("Error: -s and -r are mutually exclusive. Use one at a time.")
		os.Exit(2)
	}
	if !*scanMode && !*regenMode {
		fmt.Println("Usage: catscanner -s (scan) or -r (regenerate integrity file) [-ext \".php,.html\"] [-config path/to/config.json] [-version]")
		os.Exit(2)
	}

	// Parse extensions into a validated slice.
	extensions, err := parseExtensions(*extFlag)
	if err != nil {
		fmt.Printf("Error: %v\n", err)
		os.Exit(2)
	}

	if *regenMode {
		if err := regenerateIntegrity(extensions); err != nil {
			log.Printf("Error: %v", err)
			os.Exit(2)
		}
	}

	if *scanMode {
		os.Exit(scanFiles(extensions))
	}
}

// parseExtensions converts the comma-separated list of extensions into a slice,
// ensuring each extension starts with a dot.
func parseExtensions(extStr string) ([]string, error) {
	rawExts := strings.Split(extStr, ",")
	var exts []string
	for _, ext := range rawExts {
		trimmed := strings.TrimSpace(ext)
		if trimmed == "" {
			continue
		}
		if !strings.HasPrefix(trimmed, ".") {
			trimmed = "." + trimmed
		}
		if trimmed == "." {
			continue
		}
		exts = append(exts, trimmed)
	}
	if len(exts) == 0 {
		return nil, fmt.Errorf("no valid file extensions provided via -ext")
	}
	return exts, nil
}

// regenerateIntegrity walks through TARGET_DIR, computes SHA-256 hashes for files
// matching the provided extensions, and writes the hash and file path to the integrity file.
func regenerateIntegrity(extensions []string) error {
	tempDir := filepath.Dir(config.IntegrityFile)
	file, err := os.CreateTemp(tempDir, ".catscanner-integrity-*.tmp")
	if err != nil {
		return fmt.Errorf("failed to create temp integrity file: %w", err)
	}
	tempPath := file.Name()
	keepTemp := true
	defer func() {
		if keepTemp {
			_ = os.Remove(tempPath)
		}
	}()

	var count int
	err = filepath.Walk(config.TargetDir, func(path string, info os.FileInfo, err error) error {
		if err != nil {
			return err
		}
		if !info.IsDir() && hasValidExtension(info.Name(), extensions) {
			hash, err := computeHash(path)
			if err != nil {
				return err
			}
			if _, err := fmt.Fprintf(file, "%s  %s\n", hash, path); err != nil {
				return err
			}
			count++
		}
		return nil
	})
	if err != nil {
		file.Close()
		return fmt.Errorf("error during integrity file generation: %w", err)
	}
	if err := file.Close(); err != nil {
		return fmt.Errorf("error writing integrity file: %w", err)
	}
	if err := os.Rename(tempPath, config.IntegrityFile); err != nil {
		// Windows does not allow rename over an existing file.
		if removeErr := os.Remove(config.IntegrityFile); removeErr != nil && !os.IsNotExist(removeErr) {
			return fmt.Errorf("failed to replace integrity file: %w", err)
		}
		if renameErr := os.Rename(tempPath, config.IntegrityFile); renameErr != nil {
			return fmt.Errorf("failed to replace integrity file: %w", renameErr)
		}
	}
	keepTemp = false
	appendLog(fmt.Sprintf("Integrity file regenerated (%d files).", count))
	fmt.Printf("Integrity file regenerated (%d files).\n", count)
	return nil
}

// isWhitelisted checks if a file path matches any whitelist pattern.
//
// Patterns are matched against:
//  1. The file's base name (e.g. "*.tmp" matches any .tmp file)
//  2. The full absolute path (e.g. "/var/www/cache/foo.php")
//  3. Every suffix sub-path of the file (e.g. "cache/foo.php", "foo.php"),
//     so patterns like "cache/*" correctly match files inside a cache
//     directory regardless of whether absolute or relative paths are used.
//
// Note: filepath.Match does not support "**" globstar.
func isWhitelisted(path string, whitelist []string) bool {
	// Build a list of candidate strings to match against.
	// Start with the cleaned path and peel off one leading segment at a time.
	cleaned := filepath.ToSlash(filepath.Clean(path))
	parts := strings.Split(cleaned, "/")

	candidates := []string{
		filepath.Base(path), // bare filename
		path,                // raw path as-is
		cleaned,             // cleaned full path
	}
	// Add every trailing sub-path: "a/b/c", "b/c", "c"
	for i := range parts {
		sub := strings.Join(parts[i:], "/")
		if sub != "" {
			candidates = append(candidates, sub)
		}
	}

	for _, pattern := range whitelist {
		for _, candidate := range candidates {
			matched, err := filepath.Match(pattern, candidate)
			if err == nil && matched {
				return true
			}
		}
	}
	return false
}

// scanFiles loads the stored integrity file, rescans files in TARGET_DIR that match the provided extensions,
// compares the computed hashes with the stored values, logs discrepancies, and sends an email if needed.
// Returns exit code: 0 = clean, 1 = changes detected, 2 = error.
func scanFiles(extensions []string) int {
	// Load stored integrity data.
	storedHashes := make(map[string]string)
	content, err := os.ReadFile(config.IntegrityFile)
	if err != nil {
		log.Printf("Failed to read integrity file: %v", err)
		return 2
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
		log.Printf("Error during scanning: %v", err)
		return 2
	}

	var diffOutput strings.Builder
	var whitelistedChanges strings.Builder
	newCount, modCount, missingCount, wlCount := 0, 0, 0, 0

	// Detect new or modified files.
	for path, currentHash := range currentHashes {
		storedHash, exists := storedHashes[path]
		if !exists {
			if isWhitelisted(path, config.Whitelist) {
				whitelistedChanges.WriteString(fmt.Sprintf("Whitelisted new file: %s\n", path))
				wlCount++
			} else {
				diffOutput.WriteString(fmt.Sprintf("New file detected: %s\n", path))
				newCount++
			}
		} else if storedHash != currentHash {
			if isWhitelisted(path, config.Whitelist) {
				whitelistedChanges.WriteString(fmt.Sprintf("Whitelisted modified file: %s\n", path))
				wlCount++
			} else {
				diffOutput.WriteString(fmt.Sprintf("Modified file: %s\n", path))
				modCount++
			}
		}
	}

	// Detect files that have been removed.
	for path := range storedHashes {
		if _, exists := currentHashes[path]; !exists {
			if isWhitelisted(path, config.Whitelist) {
				whitelistedChanges.WriteString(fmt.Sprintf("Whitelisted file removed: %s\n", path))
				wlCount++
			} else {
				diffOutput.WriteString(fmt.Sprintf("File missing: %s\n", path))
				missingCount++
			}
		}
	}

	hasChanges := newCount+modCount+missingCount > 0
	hasWhitelistedChanges := wlCount > 0

	// Log all changes but only send notifications for non-whitelisted changes.
	if !hasChanges && !hasWhitelistedChanges {
		appendLog("No changes detected.")
		fmt.Println("No changes detected.")
		return 0
	}

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

	// Print a human-readable summary line.
	var parts []string
	if modCount > 0 {
		parts = append(parts, fmt.Sprintf("%d modified", modCount))
	}
	if newCount > 0 {
		parts = append(parts, fmt.Sprintf("%d new", newCount))
	}
	if missingCount > 0 {
		parts = append(parts, fmt.Sprintf("%d missing", missingCount))
	}
	if wlCount > 0 {
		parts = append(parts, fmt.Sprintf("%d whitelisted", wlCount))
	}
	fmt.Printf("Changes detected: %s\n", strings.Join(parts, ", "))

	// Only send email notification for non-whitelisted changes.
	if hasChanges {
		// Build a dynamic subject reflecting the monitored extensions.
		subject := fmt.Sprintf("Integrity Alert: changes detected in %s", config.TargetDir)
		sendEmail(subject, diffOutput.String())
		return 1
	}
	return 0
}

// hasValidExtension checks if the file's extension matches any of the allowed extensions.
func hasValidExtension(filename string, extensions []string) bool {
	fileExt := filepath.Ext(filename)
	for _, ext := range extensions {
		if fileExt == ext {
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
// Errors are reported to stderr so they surface in cron/systemd output.
func appendLog(message string) {
	f, err := os.OpenFile(config.LogFile, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0644)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Failed to write log: %v\n", err)
		return
	}
	defer f.Close()
	timestamp := time.Now().Format(time.RFC3339)
	if _, err := f.WriteString(fmt.Sprintf("%s - %s\n", timestamp, message)); err != nil {
		fmt.Fprintf(os.Stderr, "Failed to write log: %v\n", err)
	}
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

	// Sanitize headers: no newlines to prevent header injection.
	from = sanitizeHeader(from)
	to := sanitizeHeader(strings.TrimSpace(config.Email))
	subject = sanitizeHeader(subject)

	// Build RFC 5322 headers in canonical order for better deliverability.
	var sb strings.Builder
	sb.WriteString("Date: " + time.Now().Format(time.RFC1123Z) + "\r\n")
	sb.WriteString("From: " + from + "\r\n")
	sb.WriteString("To: " + to + "\r\n")
	sb.WriteString("Subject: " + subject + "\r\n")
	sb.WriteString("MIME-Version: 1.0\r\n")
	sb.WriteString("Content-Type: text/plain; charset=UTF-8\r\n")
	sb.WriteString("Content-Transfer-Encoding: 8bit\r\n")
	sb.WriteString("\r\n")
	sb.WriteString(body)
	sb.WriteString("\r\n")

	msg := []byte(sb.String())
	addr := config.SmtpServer + ":" + config.SmtpPort
	recipients := []string{strings.TrimSpace(config.Email)}
	err := smtp.SendMail(addr, auth, from, recipients, msg)
	if err != nil {
		fmt.Printf("Failed to send email via SMTP: %v\n", err)
		appendLog(fmt.Sprintf("Failed to send email via SMTP: %v", err))
	} else {
		appendLog("Email notification sent via SMTP")
	}
}

// sanitizeHeader replaces newlines in header values to prevent injection.
func sanitizeHeader(s string) string {
	return strings.ReplaceAll(strings.ReplaceAll(s, "\r", " "), "\n", " ")
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

	subject = sanitizeHeader(subject)
	args := []string{"-s", subject}
	if strings.TrimSpace(config.FromEmail) != "" {
		// Many mail implementations (mailutils) accept -a to add a header
		args = append(args, "-a", "From: "+sanitizeHeader(config.FromEmail))
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
