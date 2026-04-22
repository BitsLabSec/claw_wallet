package utils

import (
	"errors"
	"fmt"
	"net/url"
	"os"
	"regexp"
	"sandbox/internals/signer"
	"strings"
)

var sensitiveURLPattern = regexp.MustCompile(`https?://[^\s"'<>]+`)

const redactedToken = "redacted"

func TransferFromAddress(chain string, snapshot map[string]string) (string, error) {
	switch {
	case signer.IsEVMChain(chain):
		if from := snapshot["ethereum"]; from != "" {
			return from, nil
		}
	case chain == "bitcoin":
		if from := snapshot["bitcoin"]; from != "" {
			return from, nil
		}
	case chain == "solana":
		if from := snapshot["solana"]; from != "" {
			return from, nil
		}
	case chain == "sui":
		if from := snapshot["sui"]; from != "" {
			return from, nil
		}
	case chain == "tron":
		if from := snapshot["tron"]; from != "" {
			return from, nil
		}
	}
	return "", fmt.Errorf("wallet address unavailable for chain %q", chain)
}

// 原子写入文件
func AtomicWrite(path string, data []byte) error {
	dir := "."
	if idx := len(path) - len("/") - 1; idx > 0 {
		for i := len(path) - 1; i >= 0; i-- {
			if path[i] == '/' || path[i] == '\\' {
				dir = path[:i]
				break
			}
		}
	}
	tmp, err := os.CreateTemp(dir, ".clay_tmp_*")
	if err != nil {
		return fmt.Errorf("atomicWrite CreateTemp: %w", err)
	}
	tmpName := tmp.Name()
	// ensure cleanup if anything below fails
	successful := false
	defer func() {
		if !successful {
			os.Remove(tmpName)
		}
	}()

	if _, err := tmp.Write(data); err != nil {
		tmp.Close()
		return fmt.Errorf("atomicWrite Write: %w", err)
	}
	if err := tmp.Sync(); err != nil { // flush to OS buffer + kernel
		tmp.Close()
		return fmt.Errorf("atomicWrite Sync: %w", err)
	}
	if err := tmp.Close(); err != nil {
		return fmt.Errorf("atomicWrite Close: %w", err)
	}
	// Set permissions before rename so the final file is always 0600
	if err := os.Chmod(tmpName, 0600); err != nil {
		return fmt.Errorf("atomicWrite Chmod: %w", err)
	}
	if err := os.Rename(tmpName, path); err != nil {
		if removeErr := os.Remove(path); removeErr != nil && !errors.Is(removeErr, os.ErrNotExist) {
			return fmt.Errorf("atomicWrite Remove existing: %w", removeErr)
		}
		if err := os.Rename(tmpName, path); err != nil {
			return fmt.Errorf("atomicWrite Rename: %w", err)
		}
	}
	successful = true
	return nil
}

func MergeEnvKV(raw string, set map[string]string, appendOrder []string) string {
	lines := strings.Split(strings.TrimSuffix(raw, "\n"), "\n")
	done := make(map[string]bool)
	out := make([]string, 0, len(lines)+len(appendOrder))
	for _, line := range lines {
		trimmed := strings.TrimSpace(line)
		if trimmed == "" || strings.HasPrefix(trimmed, "#") {
			out = append(out, line)
			continue
		}
		i := strings.IndexByte(line, '=')
		if i > 0 {
			key := strings.TrimSpace(line[:i])
			if v, ok := set[key]; ok {
				out = append(out, key+"="+v)
				done[key] = true
				continue
			}
		}
		out = append(out, line)
	}
	for _, k := range appendOrder {
		if !done[k] {
			out = append(out, k+"="+set[k])
		}
	}
	content := strings.Join(out, "\n")
	if !strings.HasSuffix(content, "\n") {
		content += "\n"
	}
	return content
}

func SanitizeError(err error) error {
	if err == nil {
		return nil
	}
	return errors.New(SanitizeSensitiveText(err.Error()))
}

func SanitizeSensitiveText(raw string) string {
	raw = strings.TrimSpace(raw)
	if raw == "" {
		return raw
	}
	return sensitiveURLPattern.ReplaceAllStringFunc(raw, sanitizeSensitiveURL)
}

func sanitizeSensitiveURL(raw string) string {
	parsed, err := url.Parse(raw)
	if err != nil {
		return raw
	}

	segments := strings.Split(parsed.Path, "/")
	for i := 0; i < len(segments); i++ {
		if !isVersionSegment(segments[i]) || i+1 >= len(segments) {
			continue
		}
		if strings.TrimSpace(segments[i+1]) != "" {
			segments[i+1] = redactedToken
		}
	}
	parsed.Path = strings.Join(segments, "/")

	query := parsed.Query()
	for _, key := range []string{"apikey", "api_key", "key", "token", "access_token"} {
		if _, ok := query[key]; ok {
			query.Set(key, redactedToken)
		}
	}
	parsed.RawQuery = query.Encode()

	return parsed.String()
}

func isVersionSegment(segment string) bool {
	segment = strings.ToLower(strings.TrimSpace(segment))
	if len(segment) < 2 || segment[0] != 'v' {
		return false
	}
	for _, ch := range segment[1:] {
		if ch < '0' || ch > '9' {
			return false
		}
	}
	return true
}
