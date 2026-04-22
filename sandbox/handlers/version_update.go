package handlers

import (
	"encoding/json"
	"fmt"
	"io"
	"log"
	"math/rand"
	"net/http"
	"net/url"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"sync"
	"time"
)

const sandboxVersionCheckInterval = time.Hour
const sandboxVersionCheckJitter = 10 * time.Minute

var (
	versionCheckMu   sync.Mutex
	nextVersionCheck time.Time
)

type sandboxVersionResponse struct {
	LatestVersion   string `json:"latest_version"`
	CurrentVersion  string `json:"current_version,omitempty"`
	UpdateAvailable bool   `json:"update_available"`
}

func currentSandboxVersion() string {
	if strings.TrimSpace(buildVersion) == "" {
		return "dev"
	}
	return strings.TrimSpace(buildVersion)
}

func TriggerStartupVersionCheck() {
	mu.RLock()
	uid := strings.TrimSpace(boundUid)
	mu.RUnlock()
	maybeCheckForSandboxUpdateForced(uid)
}

func maybeCheckForSandboxUpdate(uid string) {
	maybeCheckForSandboxUpdateInternal(uid, false)
}

func maybeCheckForSandboxUpdateForced(uid string) {
	maybeCheckForSandboxUpdateInternal(uid, true)
}

func maybeCheckForSandboxUpdateInternal(uid string, force bool) {
	versionCheckMu.Lock()
	now := time.Now()
	if !force && !nextVersionCheck.IsZero() && now.Before(nextVersionCheck) {
		versionCheckMu.Unlock()
		return
	}
	nextVersionCheck = now.Add(nextSandboxVersionCheckDelay())
	versionCheckMu.Unlock()

	latestVersion, err := fetchLatestSandboxVersion(uid)
	if err != nil {
		log.Printf("[claw wallet sandbox] Version check failed: %v", err)
		return
	}
	currentVersion := currentSandboxVersion()
	if latestVersion == "" || latestVersion == currentVersion {
		return
	}

	log.Printf("[claw wallet sandbox] New sandbox version detected: current=%s latest=%s", currentVersion, latestVersion)
	if err := triggerSandboxBinaryUpgrade(currentVersion, latestVersion); err != nil {
		log.Printf("[claw wallet sandbox] Failed to trigger binary upgrade: %v", err)
	}
}

func nextSandboxVersionCheckDelay() time.Duration {
	jitterRange := int64(sandboxVersionCheckJitter * 2)
	if jitterRange <= 0 {
		return sandboxVersionCheckInterval
	}
	jitter := time.Duration(rand.Int63n(jitterRange)) - sandboxVersionCheckJitter
	delay := sandboxVersionCheckInterval + jitter
	if delay < 30*time.Minute {
		return 30 * time.Minute
	}
	return delay
}

func fetchLatestSandboxVersion(uid string) (string, error) {
	if relayURL == "" {
		return "", fmt.Errorf("RELAY_URL is not configured")
	}

	baseURL := strings.TrimRight(relayURL, "/") + "/agent/version"
	query := url.Values{}
	if strings.TrimSpace(uid) != "" {
		query.Set("uid", strings.TrimSpace(uid))
	}
	query.Set("current_version", currentSandboxVersion())

	req, err := http.NewRequest(http.MethodGet, baseURL+"?"+query.Encode(), nil)
	if err != nil {
		return "", err
	}
	client := &http.Client{Timeout: 15 * time.Second}
	resp, err := client.Do(req)
	if err != nil {
		return "", err
	}
	defer resp.Body.Close()

	body, err := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
	if err != nil {
		return "", err
	}
	if resp.StatusCode != http.StatusOK {
		return "", fmt.Errorf("version check HTTP %d: %s", resp.StatusCode, strings.TrimSpace(string(body)))
	}

	var payload sandboxVersionResponse
	if err := json.Unmarshal(body, &payload); err != nil {
		return "", fmt.Errorf("decode version payload: %w", err)
	}
	return strings.TrimSpace(payload.LatestVersion), nil
}

func triggerSandboxBinaryUpgrade(currentVersion, latestVersion string) error {
	scriptPath, err := resolveSandboxUpgradeScript()
	if err != nil {
		return err
	}
	exePath, err := os.Executable()
	if err != nil {
		return fmt.Errorf("resolve executable path: %w", err)
	}

	logPath, err := resolveSandboxUpdateLogPath()
	if err != nil {
		return err
	}
	logFile, err := os.OpenFile(logPath, os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0600)
	if err != nil {
		return fmt.Errorf("open update log: %w", err)
	}

	var cmd *exec.Cmd
	if runtime.GOOS == "windows" {
		cmd = exec.Command("cmd", "/C", scriptPath, "binary-upgrade", currentVersion, latestVersion, exePath, fmt.Sprintf("%d", os.Getpid()))
	} else {
		cmd = exec.Command("bash", scriptPath, "binary-upgrade", currentVersion, latestVersion, exePath, fmt.Sprintf("%d", os.Getpid()))
	}
	cmd.Stdout = logFile
	cmd.Stderr = logFile
	cmd.Dir = filepath.Dir(exePath)
	if err := cmd.Start(); err != nil {
		logFile.Close()
		return fmt.Errorf("start upgrade script: %w", err)
	}
	go func() {
		defer logFile.Close()
		_ = cmd.Wait()
	}()
	return nil
}

func resolveSandboxUpgradeScript() (string, error) {
	exePath, err := os.Executable()
	if err != nil {
		return "", fmt.Errorf("resolve executable path: %w", err)
	}
	exeDir := filepath.Dir(exePath)
	scriptDir := filepath.Join(exeDir, "upgrade_script")
	if runtime.GOOS == "windows" {
		candidates := []string{
			filepath.Join(scriptDir, "sandbox-upgrade.cmd"),
			filepath.Join(exeDir, "sandbox-upgrade.cmd"),
		}
		for _, scriptPath := range candidates {
			if _, err := os.Stat(scriptPath); err == nil {
				return scriptPath, nil
			}
		}
		if err := downloadWindowsUpgradeScripts(scriptDir); err != nil {
			return "", err
		}
		return filepath.Join(scriptDir, "sandbox-upgrade.cmd"), nil
	}
	candidates := []string{
		filepath.Join(scriptDir, "sandbox-upgrade.sh"),
		filepath.Join(exeDir, "sandbox-upgrade.sh"),
	}
	for _, scriptPath := range candidates {
		if _, err := os.Stat(scriptPath); err == nil {
			return scriptPath, nil
		}
	}
	if err := downloadUpgradeScript(filepath.Join(scriptDir, "sandbox-upgrade.sh"), "sandbox-upgrade.sh", 0755); err != nil {
		return "", err
	}
	return filepath.Join(scriptDir, "sandbox-upgrade.sh"), nil
}

func resolveSandboxUpdateLogPath() (string, error) {
	exePath, err := os.Executable()
	if err != nil {
		return "", fmt.Errorf("resolve executable path: %w", err)
	}
	return filepath.Join(filepath.Dir(exePath), "sandbox-update.log"), nil
}

func downloadWindowsUpgradeScripts(scriptDir string) error {
	if err := downloadUpgradeScript(filepath.Join(scriptDir, "sandbox-upgrade.cmd"), "sandbox-upgrade.cmd", 0644); err != nil {
		return err
	}
	if err := downloadUpgradeScript(filepath.Join(scriptDir, "sandbox-upgrade.ps1"), "sandbox-upgrade.ps1", 0644); err != nil {
		return err
	}
	return nil
}

func downloadUpgradeScript(localPath, remoteName string, mode os.FileMode) error {
	if err := os.MkdirAll(filepath.Dir(localPath), 0755); err != nil {
		return fmt.Errorf("create upgrade script dir: %w", err)
	}
	scriptBaseURL := env("UPGRADE_SCRIPT_BASE_URL", upgradeScriptBaseURL)
	resp, err := http.Get(scriptBaseURL + "/" + remoteName)
	if err != nil {
		return fmt.Errorf("download upgrade script %s: %w", remoteName, err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(io.LimitReader(resp.Body, 4096))
		return fmt.Errorf("download upgrade script %s HTTP %d: %s", remoteName, resp.StatusCode, strings.TrimSpace(string(body)))
	}

	tmpPath := localPath + ".download"
	file, err := os.OpenFile(tmpPath, os.O_CREATE|os.O_WRONLY|os.O_TRUNC, mode)
	if err != nil {
		return fmt.Errorf("create local upgrade script %s: %w", localPath, err)
	}
	if _, err := io.Copy(file, resp.Body); err != nil {
		file.Close()
		_ = os.Remove(tmpPath)
		return fmt.Errorf("write local upgrade script %s: %w", localPath, err)
	}
	if err := file.Close(); err != nil {
		_ = os.Remove(tmpPath)
		return fmt.Errorf("close local upgrade script %s: %w", localPath, err)
	}
	if err := os.Chmod(tmpPath, mode); err != nil && runtime.GOOS != "windows" {
		_ = os.Remove(tmpPath)
		return fmt.Errorf("chmod local upgrade script %s: %w", localPath, err)
	}
	if err := os.Rename(tmpPath, localPath); err != nil {
		_ = os.Remove(tmpPath)
		return fmt.Errorf("install local upgrade script %s: %w", localPath, err)
	}
	if runtime.GOOS != "windows" {
		if err := os.Chmod(localPath, mode); err != nil {
			return fmt.Errorf("chmod local upgrade script %s: %w", localPath, err)
		}
	}
	return nil
}
