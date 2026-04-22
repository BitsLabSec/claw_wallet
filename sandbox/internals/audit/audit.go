package audit

import (
	"encoding/json"
	"log"
	"os"
	"strings"
	"sync"
	"time"
)

var (
	auditPath string
	mu        sync.Mutex
)

func Init(path string) {
	auditPath = path
	// Create or verify the file exists and is 0600
	f, err := os.OpenFile(auditPath, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0600)
	if err != nil {
		log.Printf("[claw wallet sandbox audit] Warning: could not open audit log: %v", err)
		return
	}
	f.Close()
	// Ensure strict permissions just in case
	os.Chmod(auditPath, 0600)
}

// LogEvent appends a structured JSON event to the audit log.
func LogEvent(eventType, uid, runtimeID, status, details string) {
	mu.Lock()
	defer mu.Unlock()

	if auditPath == "" {
		return
	}

	entry := map[string]string{
		"timestamp":  time.Now().UTC().Format(time.RFC3339),
		"event_type": eventType, // e.g., "wallet_init", "tx_sign"
		"uid":        uid,
		"runtime_id": runtimeID,
		"status":     status, // e.g., "accepted", "rejected", "failed"
		"details":    details,
	}

	data, err := json.Marshal(entry)
	if err != nil {
		return
	}
	data = append(data, '\n')

	f, err := os.OpenFile(auditPath, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0600)
	if err == nil {
		f.Write(data)
		f.Sync() // Ensure it goes to disk
		f.Close()
	}
}

// GetLogs returns the last N lines from the audit log
func GetLogs(limit int) []map[string]string {
	mu.Lock()
	defer mu.Unlock()

	data, err := os.ReadFile(auditPath)
	if err != nil {
		return []map[string]string{}
	}

	lines := strings.Split(strings.TrimSpace(string(data)), "\n")
	if len(lines) == 0 {
		return []map[string]string{}
	}

	start := 0
	if len(lines) > limit {
		start = len(lines) - limit
	}

	res := []map[string]string{}
	for i := len(lines) - 1; i >= start; i-- {
		if lines[i] == "" {
			continue
		}
		var entry map[string]string
		if err := json.Unmarshal([]byte(lines[i]), &entry); err == nil {
			res = append(res, entry)
		}
	}
	return res
}
