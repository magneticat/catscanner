package main

import (
	"encoding/json"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
)

var testBinary string

func TestMain(m *testing.M) {
	dir, err := os.MkdirTemp("", "catscanner-testbin-")
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
	defer os.RemoveAll(dir)

	testBinary = filepath.Join(dir, "catscanner")
	if runtime.GOOS == "windows" {
		testBinary += ".exe"
	}
	cmd := exec.Command("go", "build", "-o", testBinary, ".")
	if out, err := cmd.CombinedOutput(); err != nil {
		fmt.Fprintf(os.Stderr, "build test binary: %v\n%s", err, out)
		os.Exit(1)
	}
	os.Exit(m.Run())
}

func setupEnv(t *testing.T) string {
	t.Helper()
	orig := config
	t.Cleanup(func() { config = orig })

	root := t.TempDir()
	webroot := filepath.Join(root, "web")
	logs := filepath.Join(root, "logs")
	if err := os.MkdirAll(webroot, 0755); err != nil {
		t.Fatal(err)
	}
	if err := os.MkdirAll(logs, 0755); err != nil {
		t.Fatal(err)
	}
	config = Config{
		TargetDir:     webroot,
		IntegrityFile: filepath.Join(logs, "integrity.txt"),
		LogFile:       filepath.Join(logs, "integrity.log"),
	}
	return webroot
}

func writeFile(t *testing.T, path, content string) {
	t.Helper()
	if err := os.MkdirAll(filepath.Dir(path), 0755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, []byte(content), 0644); err != nil {
		t.Fatal(err)
	}
}

func setExcludes(t *testing.T, entries ...string) {
	t.Helper()
	dirs, err := parseExcludeDirs(entries, config.TargetDir)
	if err != nil {
		t.Fatalf("parseExcludeDirs(%v): %v", entries, err)
	}
	config.ExcludeDirs = dirs
}

func regen(t *testing.T, exts ...string) {
	t.Helper()
	if len(exts) == 0 {
		exts = []string{".php"}
	}
	if err := regenerateIntegrity(exts); err != nil {
		t.Fatalf("regenerateIntegrity: %v", err)
	}
}

func captureStdout(t *testing.T, fn func()) string {
	t.Helper()
	old := os.Stdout
	r, w, err := os.Pipe()
	if err != nil {
		t.Fatal(err)
	}
	os.Stdout = w
	fn()
	w.Close()
	os.Stdout = old
	b, err := io.ReadAll(r)
	r.Close()
	if err != nil {
		t.Fatal(err)
	}
	return string(b)
}

func scan(t *testing.T, exts ...string) (string, int) {
	t.Helper()
	if len(exts) == 0 {
		exts = []string{".php"}
	}
	var code int
	out := captureStdout(t, func() {
		code = scanFiles(exts)
	})
	return out, code
}

func baseline(t *testing.T) string {
	t.Helper()
	data, err := os.ReadFile(config.IntegrityFile)
	if err != nil {
		t.Fatalf("read baseline: %v", err)
	}
	return string(data)
}

func writeConfigFile(t *testing.T, dir string, cfg map[string]interface{}) string {
	t.Helper()
	path := filepath.Join(dir, "config.json")
	data, err := json.MarshalIndent(cfg, "", "    ")
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, data, 0644); err != nil {
		t.Fatal(err)
	}
	return path
}

func runCLI(t *testing.T, args ...string) (string, int) {
	t.Helper()
	cmd := exec.Command(testBinary, args...)
	out, err := cmd.CombinedOutput()
	return string(out), exitCode(err)
}

func exitCode(err error) int {
	if err == nil {
		return 0
	}
	if ee, ok := err.(*exec.ExitError); ok {
		return ee.ExitCode()
	}
	return -1
}

func assertContains(t *testing.T, got, want string) {
	t.Helper()
	if !strings.Contains(got, want) {
		t.Fatalf("expected %q to contain %q", got, want)
	}
}

func assertNotContains(t *testing.T, got, want string) {
	t.Helper()
	if strings.Contains(got, want) {
		t.Fatalf("expected %q not to contain %q", got, want)
	}
}

func TestParseExtensions(t *testing.T) {
	t.Run("lowercase and dedupe", func(t *testing.T) {
		got, err := parseExtensions(".PHP, php, .Html, HTML")
		if err != nil {
			t.Fatal(err)
		}
		want := []string{".php", ".html"}
		if len(got) != len(want) {
			t.Fatalf("got %v, want %v", got, want)
		}
		for i := range want {
			if got[i] != want[i] {
				t.Fatalf("got %v, want %v", got, want)
			}
		}
	})
	t.Run("optional leading dot", func(t *testing.T) {
		got, err := parseExtensions("js")
		if err != nil {
			t.Fatal(err)
		}
		if len(got) != 1 || got[0] != ".js" {
			t.Fatalf("got %v, want [.js]", got)
		}
	})
	t.Run("empty", func(t *testing.T) {
		if _, err := parseExtensions(""); err == nil {
			t.Fatal("expected error for empty -ext")
		}
	})
	t.Run("only separators", func(t *testing.T) {
		if _, err := parseExtensions(",, , ."); err == nil {
			t.Fatal("expected error for invalid -ext")
		}
	})
	t.Run("path separator rejected", func(t *testing.T) {
		if _, err := parseExtensions(".php,/etc/passwd"); err == nil {
			t.Fatal("expected error for extension containing a path separator")
		}
	})
}

func TestHasValidExtension(t *testing.T) {
	exts := []string{".php"}
	if !hasValidExtension("example.PHP", exts) {
		t.Fatal("example.PHP should match .php")
	}
	if !hasValidExtension("example.php", exts) {
		t.Fatal("example.php should match .php")
	}
	if !hasValidExtension("example.PhP", exts) {
		t.Fatal("example.PhP should match .php")
	}
	if hasValidExtension("example.js", exts) {
		t.Fatal("example.js should not match .php")
	}
}

func TestParseExcludeDirs(t *testing.T) {
	target := t.TempDir()

	t.Run("omitted and empty", func(t *testing.T) {
		got, err := parseExcludeDirs(nil, target)
		if err != nil || got != nil {
			t.Fatalf("nil: got %v err %v", got, err)
		}
		got, err = parseExcludeDirs([]string{}, target)
		if err != nil || got != nil {
			t.Fatalf("empty: got %v err %v", got, err)
		}
	})

	t.Run("normalize slash and trailing separator", func(t *testing.T) {
		got, err := parseExcludeDirs([]string{
			"internal_data/attachments",
			"internal_data/attachments/",
			"internal_data/code_cache",
			"internal_data/temp",
		}, target)
		if err != nil {
			t.Fatal(err)
		}
		if len(got) != 3 {
			t.Fatalf("got %v, want 3 unique entries", got)
		}
		if got[0] != filepath.Clean(filepath.FromSlash("internal_data/attachments")) {
			t.Fatalf("first entry: %q", got[0])
		}
	})

	t.Run("empty entry", func(t *testing.T) {
		if _, err := parseExcludeDirs([]string{" "}, target); err == nil {
			t.Fatal("expected error for empty entry")
		}
	})

	t.Run("dot", func(t *testing.T) {
		if _, err := parseExcludeDirs([]string{"."}, target); err == nil {
			t.Fatal("expected error for .")
		}
		if _, err := parseExcludeDirs([]string{"foo/.."}, target); err == nil {
			t.Fatal("expected error for path that cleans to .")
		}
	})

	t.Run("absolute", func(t *testing.T) {
		abs := filepath.Join(target, "outside")
		if _, err := parseExcludeDirs([]string{abs}, target); err == nil {
			t.Fatal("expected error for absolute path")
		}
	})

	t.Run("escapes target", func(t *testing.T) {
		cases := []string{"..", "../outside", "foo/../../outside", "internal_data/../../../etc"}
		for _, c := range cases {
			if _, err := parseExcludeDirs([]string{c}, target); err == nil {
				t.Fatalf("expected error for escaping path %q", c)
			}
		}
	})
}

func TestCleanBaselineAndScan(t *testing.T) {
	web := setupEnv(t)
	writeFile(t, filepath.Join(web, "index.php"), "<?php echo 1; ?>")
	regen(t)
	out, code := scan(t)
	if code != 0 {
		t.Fatalf("clean scan exit %d, output %q", code, out)
	}
	assertContains(t, out, "No changes detected.")
}

func TestNewModifiedDeleted(t *testing.T) {
	t.Run("new", func(t *testing.T) {
		web := setupEnv(t)
		writeFile(t, filepath.Join(web, "index.php"), "<?php echo 1; ?>")
		regen(t)
		writeFile(t, filepath.Join(web, "new-file.php"), "<?php echo 'new'; ?>")
		out, code := scan(t)
		if code != 1 {
			t.Fatalf("new file exit %d, want 1; output %q", code, out)
		}
		assertContains(t, out, "Changes detected:")
		assertContains(t, out, "1 new")
	})

	t.Run("modified", func(t *testing.T) {
		web := setupEnv(t)
		index := filepath.Join(web, "index.php")
		writeFile(t, index, "<?php echo 1; ?>")
		regen(t)
		writeFile(t, index, "<?php echo 2; ?>")
		out, code := scan(t)
		if code != 1 {
			t.Fatalf("modified file exit %d, want 1; output %q", code, out)
		}
		assertContains(t, out, "1 modified")
	})

	t.Run("deleted", func(t *testing.T) {
		web := setupEnv(t)
		writeFile(t, filepath.Join(web, "index.php"), "<?php echo 1; ?>")
		gone := filepath.Join(web, "old.php")
		writeFile(t, gone, "<?php echo 'gone'; ?>")
		regen(t)
		if err := os.Remove(gone); err != nil {
			t.Fatal(err)
		}
		out, code := scan(t)
		if code != 1 {
			t.Fatalf("deleted file exit %d, want 1; output %q", code, out)
		}
		assertContains(t, out, "1 missing")
	})
}

func TestMixedCaseExtensions(t *testing.T) {
	web := setupEnv(t)
	writeFile(t, filepath.Join(web, "index.php"), "lower")
	writeFile(t, filepath.Join(web, "Page.PHP"), "upper")
	writeFile(t, filepath.Join(web, "Mixed.PhP"), "mixed")
	writeFile(t, filepath.Join(web, "ignore.js"), "nope")
	regen(t, ".php")

	body := baseline(t)
	assertContains(t, body, "index.php")
	assertContains(t, body, "Page.PHP")
	assertContains(t, body, "Mixed.PhP")
	assertNotContains(t, body, "ignore.js")

	out, code := scan(t, ".php")
	if code != 0 {
		t.Fatalf("clean mixed-case scan exit %d, output %q", code, out)
	}
}

func TestExcludeDirsAbsentFromBaseline(t *testing.T) {
	web := setupEnv(t)
	writeFile(t, filepath.Join(web, "index.php"), "ok")
	writeFile(t, filepath.Join(web, "internal_data", "attachments", "file.php"), "hidden")
	writeFile(t, filepath.Join(web, "internal_data", "code_cache", "cache.php"), "hidden")
	writeFile(t, filepath.Join(web, "internal_data", "temp", "tmp.php"), "hidden")
	setExcludes(t, "internal_data/attachments", "internal_data/code_cache", "internal_data/temp")
	regen(t)

	body := baseline(t)
	assertContains(t, body, "index.php")
	assertNotContains(t, body, "attachments")
	assertNotContains(t, body, "code_cache")
	assertNotContains(t, filepath.ToSlash(body), "internal_data/temp")
}

func TestExcludeDirsChangesProduceNoAlert(t *testing.T) {
	web := setupEnv(t)
	writeFile(t, filepath.Join(web, "index.php"), "ok")
	hidden := filepath.Join(web, "internal_data", "attachments", "file.php")
	writeFile(t, hidden, "v1")
	setExcludes(t, "internal_data/attachments")
	regen(t)

	writeFile(t, hidden, "v2")
	writeFile(t, filepath.Join(web, "internal_data", "attachments", "new.php"), "new")
	if err := os.Remove(hidden); err != nil {
		t.Fatal(err)
	}

	out, code := scan(t)
	if code != 0 {
		t.Fatalf("excluded changes should not alert, exit %d output %q", code, out)
	}
	assertContains(t, out, "No changes detected.")
}

func TestExcludeDirsNestedPruned(t *testing.T) {
	web := setupEnv(t)
	writeFile(t, filepath.Join(web, "index.php"), "ok")
	writeFile(t, filepath.Join(web, "internal_data", "attachments", "nested", "deep", "nested-deep.php"), "deep")
	setExcludes(t, "internal_data")
	regen(t)

	body := baseline(t)
	assertContains(t, body, "index.php")
	assertNotContains(t, body, "attachments")
	assertNotContains(t, body, "nested-deep.php")
}

func TestExcludeDirsAddDoesNotReportMissing(t *testing.T) {
	web := setupEnv(t)
	writeFile(t, filepath.Join(web, "index.php"), "ok")
	writeFile(t, filepath.Join(web, "internal_data", "attachments", "file.php"), "hidden")
	regen(t)
	assertContains(t, baseline(t), "file.php")

	setExcludes(t, "internal_data/attachments")
	out, code := scan(t)
	if code != 0 {
		t.Fatalf("adding an exclusion should not report missing files, exit %d output %q", code, out)
	}
	assertContains(t, out, "No changes detected.")
	assertNotContains(t, out, "missing")
}

func TestExcludeDirsRemoveAppearsNew(t *testing.T) {
	web := setupEnv(t)
	writeFile(t, filepath.Join(web, "index.php"), "ok")
	writeFile(t, filepath.Join(web, "internal_data", "attachments", "file.php"), "hidden")
	setExcludes(t, "internal_data/attachments")
	regen(t)
	assertNotContains(t, baseline(t), "file.php")

	setExcludes(t)
	out, code := scan(t)
	if code != 1 {
		t.Fatalf("removing an exclusion should report new files, exit %d output %q", code, out)
	}
	assertContains(t, out, "1 new")
}

func TestWhitelistSuppressesNotification(t *testing.T) {
	web := setupEnv(t)
	writeFile(t, filepath.Join(web, "index.php"), "ok")
	cached := filepath.Join(web, "cache", "foo.php")
	writeFile(t, cached, "v1")
	config.Whitelist = []string{"cache/*"}
	regen(t)
	assertContains(t, baseline(t), "foo.php")

	writeFile(t, cached, "v2")
	out, code := scan(t)
	if code != 0 {
		t.Fatalf("whitelisted modification should not notify, exit %d output %q", code, out)
	}
	assertContains(t, out, "1 whitelisted")
	assertNotContains(t, out, "1 modified")

	writeFile(t, filepath.Join(web, "cache", "bar.php"), "new")
	out, code = scan(t)
	if code != 0 {
		t.Fatalf("whitelisted new file should not notify, exit %d output %q", code, out)
	}
	assertContains(t, out, "whitelisted")
}

func TestLoadConfigExcludeDirs(t *testing.T) {
	orig := config
	t.Cleanup(func() { config = orig })

	dir := t.TempDir()
	web := filepath.Join(dir, "web")
	logs := filepath.Join(dir, "logs")
	if err := os.MkdirAll(web, 0755); err != nil {
		t.Fatal(err)
	}
	if err := os.MkdirAll(logs, 0755); err != nil {
		t.Fatal(err)
	}

	t.Run("valid", func(t *testing.T) {
		path := writeConfigFile(t, dir, map[string]interface{}{
			"target_dir":     web,
			"integrity_file": filepath.Join(logs, "integrity.txt"),
			"log_file":       filepath.Join(logs, "integrity.log"),
			"exclude_dirs":   []string{"internal_data/attachments"},
			"whitelist":      []string{"*.tmp"},
		})
		if err := loadConfig(path); err != nil {
			t.Fatal(err)
		}
		if len(config.ExcludeDirs) != 1 {
			t.Fatalf("expected 1 exclude dir, got %v", config.ExcludeDirs)
		}
		if len(config.Whitelist) != 1 || config.Whitelist[0] != "*.tmp" {
			t.Fatalf("whitelist changed: %v", config.Whitelist)
		}
	})

	t.Run("omitted exclude_dirs remains compatible", func(t *testing.T) {
		path := writeConfigFile(t, dir, map[string]interface{}{
			"target_dir":     web,
			"integrity_file": filepath.Join(logs, "integrity.txt"),
			"log_file":       filepath.Join(logs, "integrity.log"),
		})
		if err := loadConfig(path); err != nil {
			t.Fatal(err)
		}
		if len(config.ExcludeDirs) != 0 {
			t.Fatalf("expected no exclusions, got %v", config.ExcludeDirs)
		}
	})

	t.Run("escaping rejected", func(t *testing.T) {
		path := writeConfigFile(t, dir, map[string]interface{}{
			"target_dir":     web,
			"integrity_file": filepath.Join(logs, "integrity.txt"),
			"log_file":       filepath.Join(logs, "integrity.log"),
			"exclude_dirs":   []string{"../outside"},
		})
		if err := loadConfig(path); err == nil {
			t.Fatal("expected loadConfig to reject escaping exclude_dirs")
		}
	})
}

func TestCLIMutuallyExclusiveOrMissingModes(t *testing.T) {
	dir := t.TempDir()
	web := filepath.Join(dir, "web")
	logs := filepath.Join(dir, "logs")
	os.MkdirAll(web, 0755)
	os.MkdirAll(logs, 0755)
	cfg := writeConfigFile(t, dir, map[string]interface{}{
		"target_dir":     web,
		"integrity_file": filepath.Join(logs, "integrity.txt"),
		"log_file":       filepath.Join(logs, "integrity.log"),
	})

	out, code := runCLI(t, "-s", "-r", "-config", cfg)
	if code != 2 {
		t.Fatalf("both modes: exit %d want 2; output %q", code, out)
	}
	assertContains(t, out, "mutually exclusive")

	out, code = runCLI(t, "-config", cfg)
	if code != 2 {
		t.Fatalf("neither mode: exit %d want 2; output %q", code, out)
	}
	assertContains(t, out, "Usage:")
}

func TestCLIInvalidExtensions(t *testing.T) {
	dir := t.TempDir()
	web := filepath.Join(dir, "web")
	logs := filepath.Join(dir, "logs")
	os.MkdirAll(web, 0755)
	os.MkdirAll(logs, 0755)
	cfg := writeConfigFile(t, dir, map[string]interface{}{
		"target_dir":     web,
		"integrity_file": filepath.Join(logs, "integrity.txt"),
		"log_file":       filepath.Join(logs, "integrity.log"),
	})

	out, code := runCLI(t, "-r", "-ext", ",, , .", "-config", cfg)
	if code != 2 {
		t.Fatalf("invalid ext: exit %d want 2; output %q", code, out)
	}
	assertContains(t, out, "no valid file extensions")

	out, code = runCLI(t, "-s", "-ext", ".php,/tmp", "-config", cfg)
	if code != 2 {
		t.Fatalf("path ext: exit %d want 2; output %q", code, out)
	}
	assertContains(t, out, "invalid file extension")
}

func TestCLIConfigLoadErrors(t *testing.T) {
	dir := t.TempDir()

	out, code := runCLI(t, "-s", "-config", filepath.Join(dir, "missing.json"))
	if code != 2 {
		t.Fatalf("missing config: exit %d want 2; output %q", code, out)
	}
	assertContains(t, out, "Error loading configuration")

	badJSON := filepath.Join(dir, "bad.json")
	if err := os.WriteFile(badJSON, []byte("{"), 0644); err != nil {
		t.Fatal(err)
	}
	out, code = runCLI(t, "-s", "-config", badJSON)
	if code != 2 {
		t.Fatalf("invalid json: exit %d want 2; output %q", code, out)
	}

	incomplete := writeConfigFile(t, dir, map[string]interface{}{
		"integrity_file": "x",
		"log_file":       "y",
	})
	out, code = runCLI(t, "-s", "-config", incomplete)
	if code != 2 {
		t.Fatalf("missing target_dir: exit %d want 2; output %q", code, out)
	}
	assertContains(t, out, "target_dir is required")

	web := filepath.Join(dir, "web")
	logs := filepath.Join(dir, "logs")
	if err := os.MkdirAll(web, 0755); err != nil {
		t.Fatal(err)
	}
	if err := os.MkdirAll(logs, 0755); err != nil {
		t.Fatal(err)
	}
	escDir := filepath.Join(dir, "esc")
	if err := os.MkdirAll(escDir, 0755); err != nil {
		t.Fatal(err)
	}
	escaping := writeConfigFile(t, escDir, map[string]interface{}{
		"target_dir":     web,
		"integrity_file": filepath.Join(logs, "integrity.txt"),
		"log_file":       filepath.Join(logs, "integrity.log"),
		"exclude_dirs":   []string{"../outside"},
	})
	out, code = runCLI(t, "-s", "-config", escaping)
	if code != 2 {
		t.Fatalf("escaping exclude: exit %d want 2; output %q", code, out)
	}
	assertContains(t, out, "escapes target_dir")
}

func TestCLIVersion(t *testing.T) {
	out, code := runCLI(t, "-version")
	if code != 0 {
		t.Fatalf("version exit %d want 0; output %q", code, out)
	}
	assertContains(t, out, "catscanner 1.1.0")
}

func TestDirectorySymlinkNotFollowed(t *testing.T) {
	web := setupEnv(t)
	writeFile(t, filepath.Join(web, "index.php"), "ok")

	outside := t.TempDir()
	writeFile(t, filepath.Join(outside, "secret.php"), "secret")
	link := filepath.Join(web, "linked")
	if err := os.Symlink(outside, link); err != nil {
		t.Skipf("symlinks not supported: %v", err)
	}

	regen(t)
	body := baseline(t)
	assertContains(t, body, "index.php")
	assertNotContains(t, body, "secret.php")
}
