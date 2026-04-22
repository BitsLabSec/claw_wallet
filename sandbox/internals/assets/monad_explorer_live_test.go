package assets

import (
	"io"
	"net/http"
	"os"
	"strings"
	"testing"
	"time"
)

func TestMonadExplorerLiveProbe(t *testing.T) {
	if !strings.EqualFold(strings.TrimSpace(os.Getenv("CLAY_RUN_MONAD_EXPLORER_LIVE_TESTS")), "1") {
		t.Skip("set CLAY_RUN_MONAD_EXPLORER_LIVE_TESTS=1 to run monad explorer probe")
	}

	address := strings.TrimSpace(os.Getenv("TEST_OC_MONAD"))
	if address == "" {
		t.Skip("TEST_OC_MONAD is not set")
	}

	url := "https://monadscan.com/address/" + address
	httpClient := &http.Client{Timeout: 12 * time.Second}

	for i := 0; i < 3; i++ {
		startedAt := time.Now()
		req, err := http.NewRequest(http.MethodGet, url, nil)
		if err != nil {
			t.Fatalf("probe %d create request: %v", i+1, err)
		}
		req.Header.Set("User-Agent", "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/135.0.0.0 Safari/537.36")
		req.Header.Set("Accept", "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8")
		req.Header.Set("Accept-Language", "en-US,en;q=0.9")

		resp, err := httpClient.Do(req)
		if err != nil {
			t.Fatalf("probe %d http error after %s: %v", i+1, time.Since(startedAt).Round(time.Millisecond), err)
		}
		body, readErr := io.ReadAll(io.LimitReader(resp.Body, 512*1024))
		_ = resp.Body.Close()
		if readErr != nil {
			t.Fatalf("probe %d read body after %s: %v", i+1, time.Since(startedAt).Round(time.Millisecond), readErr)
		}
		if resp.StatusCode != http.StatusOK {
			t.Fatalf("probe %d got status %d after %s", i+1, resp.StatusCode, time.Since(startedAt).Round(time.Millisecond))
		}

		html := strings.ToLower(string(body))
		if !strings.Contains(html, strings.ToLower(address)) && !strings.Contains(html, "transactions") && !strings.Contains(html, "mon balance") {
			t.Fatalf("probe %d returned 200 but missing expected monadscan markers after %s", i+1, time.Since(startedAt).Round(time.Millisecond))
		}
		t.Logf("probe=%d status=%d elapsed=%s size=%d", i+1, resp.StatusCode, time.Since(startedAt).Round(time.Millisecond), len(body))
	}
}
