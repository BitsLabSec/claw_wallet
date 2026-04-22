package cli

import (
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestBackup0GCLIPostsOptionalPayload(t *testing.T) {
	prevDir, err := os.Getwd()
	if err != nil {
		t.Fatalf("Getwd failed: %v", err)
	}
	tmp := t.TempDir()
	t.Cleanup(func() {
		_ = os.Chdir(prevDir)
	})
	if err := os.Chdir(tmp); err != nil {
		t.Fatalf("Chdir failed: %v", err)
	}

	var gotMethod, gotPath, gotBody string
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotMethod = r.Method
		gotPath = r.URL.Path
		body, _ := io.ReadAll(r.Body)
		gotBody = strings.TrimSpace(string(body))
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"status":"ok"}`))
	}))
	t.Cleanup(server.Close)

	if err := os.WriteFile(".env.clay", []byte("LISTEN_ADDR="+server.URL+"\n"), 0o600); err != nil {
		t.Fatalf("write env failed: %v", err)
	}
	payloadPath := filepath.Join(tmp, "backup_0g.json")
	payload := `{"rpc_url":"https://evmrpc-testnet.0g.ai","vault_address":"0x1111111111111111111111111111111111111111"}`
	if err := os.WriteFile(payloadPath, []byte(payload), 0o600); err != nil {
		t.Fatalf("write payload failed: %v", err)
	}

	handled, err := RunCLI([]string{"backup0g", payloadPath})
	if err != nil {
		t.Fatalf("RunCLI failed: %v", err)
	}
	if !handled {
		t.Fatal("expected backup0g command to be handled")
	}
	if gotMethod != http.MethodPost || gotPath != "/api/v1/wallet/backup/0g" {
		t.Fatalf("unexpected request %s %s", gotMethod, gotPath)
	}
	if gotBody != payload {
		t.Fatalf("unexpected request body %q", gotBody)
	}
}
