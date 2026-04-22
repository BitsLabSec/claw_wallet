package assets

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

func TestMonadTopicAddressValidation(t *testing.T) {
	withPrefix, err := monadTopicAddress("0xabc123")
	if err != nil {
		t.Fatalf("monadTopicAddress returned error for 0x-prefixed input: %v", err)
	}
	withoutPrefix, err := monadTopicAddress("abc123")
	if err != nil {
		t.Fatalf("monadTopicAddress returned error for prefix-less input: %v", err)
	}
	if withPrefix != withoutPrefix {
		t.Fatalf("expected equivalent topics, got %q and %q", withPrefix, withoutPrefix)
	}
	if want := "0x0000000000000000000000000000000000000000000000000000000000abc123"; withPrefix != want {
		t.Fatalf("monadTopicAddress returned %q, want %q", withPrefix, want)
	}

	if _, err := monadTopicAddress("0x" + strings.Repeat("a", 65)); err == nil {
		t.Fatal("expected oversized address to return an error")
	}
	if _, err := monadTopicAddress("0xabcxyz"); err == nil {
		t.Fatal("expected non-hex address to return an error")
	}
}

func TestRefreshChainCacheKeepsMonadAssetsWhenHistoryFails(t *testing.T) {
	const address = "0xf4c6940cea946f9df0361bc4c733878107326def"

	prevBase := monadScanAPIBase
	prevClient := client
	t.Cleanup(func() {
		monadScanAPIBase = prevBase
		client = prevClient
		mu.Lock()
		delete(globalCache, "monad:"+address)
		mu.Unlock()
	})

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		if r.Method == http.MethodGet {
			http.Error(w, "monadscan unavailable", http.StatusBadGateway)
			return
		}

		var payload map[string]any
		if err := json.NewDecoder(r.Body).Decode(&payload); err != nil {
			t.Fatalf("decode payload: %v", err)
		}

		switch payload["method"] {
		case "eth_getBalance":
			_, _ = w.Write([]byte(`{"jsonrpc":"2.0","id":1,"result":"0xde0b6b3a7640000"}`))
		case "alchemy_getTokenBalances":
			_, _ = w.Write([]byte(`{"jsonrpc":"2.0","id":1,"result":{"tokenBalances":[]}}`))
		default:
			_, _ = w.Write([]byte(`{"jsonrpc":"2.0","id":1,"error":{"code":-32000,"message":"history unavailable"}}`))
		}
	}))
	defer server.Close()

	t.Setenv("CLAY_RPC_MONAD", server.URL)
	t.Setenv(monadScanPrimaryAPIKeyEnv, "primary")
	t.Setenv(monadScanFallbackAPIKeyEnv, "")
	monadScanAPIBase = server.URL
	client = &http.Client{Timeout: 100 * time.Millisecond}

	refreshChainCache("monad", address, true)

	mu.RLock()
	cached, ok := globalCache["monad:"+address]
	mu.RUnlock()
	if !ok {
		t.Fatal("expected monad cache entry to be written")
	}
	if len(cached.Assets) != 1 {
		t.Fatalf("expected 1 asset, got %d", len(cached.Assets))
	}
	if cached.Assets[0].Chain != "monad" || cached.Assets[0].ContractAddress != "native" || cached.Assets[0].BalanceStr != "1000000000000000000" {
		t.Fatalf("unexpected cached assets: %+v", cached.Assets)
	}
	if len(cached.History) != 0 {
		t.Fatalf("expected empty history fallback, got %+v", cached.History)
	}
}

func TestFetchMonadFastChainDataUsesExplorerHistoryAndRPCBalances(t *testing.T) {
	const address = "0x66078cbd01b67418dabccd4acca065466b22afc8"
	const token = "0x000000000000000000000000000000000000beef"

	prevBase := monadScanAPIBase
	prevClient := client
	t.Cleanup(func() {
		monadScanAPIBase = prevBase
		client = prevClient
	})

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		if r.Method == http.MethodGet {
			action := r.URL.Query().Get("action")
			switch action {
			case "txlist":
				_, _ = w.Write([]byte(`{"status":"1","message":"OK","result":[{"hash":"0xaaa","from":"` + address + `","to":"0x1111111111111111111111111111111111111111","value":"1000000000000000000","timeStamp":"1712145600","txreceipt_status":"1","isError":"0"}]}`))
			case "txlistinternal":
				_, _ = w.Write([]byte(`{"status":"0","message":"No transactions found","result":"No transactions found"}`))
			case "tokentx":
				_, _ = w.Write([]byte(`{"status":"1","message":"OK","result":[{"hash":"0xbbb","from":"0x2222222222222222222222222222222222222222","to":"` + address + `","value":"2500000","timeStamp":"1712145660","tokenSymbol":"FAST","tokenDecimal":"6","contractAddress":"` + token + `"}]}`))
			default:
				http.NotFound(w, r)
			}
			return
		}

		var payload map[string]any
		if err := json.NewDecoder(r.Body).Decode(&payload); err != nil {
			t.Fatalf("decode payload: %v", err)
		}
		switch payload["method"] {
		case "eth_getBalance":
			_, _ = w.Write([]byte(`{"jsonrpc":"2.0","id":1,"result":"0xde0b6b3a7640000"}`))
		case "eth_call":
			params, _ := payload["params"].([]any)
			callObj, _ := params[0].(map[string]any)
			data := strings.ToLower(strings.TrimSpace(stringValue(callObj["data"])))
			switch {
			case strings.HasPrefix(data, "0x70a08231"):
				_, _ = w.Write([]byte(`{"jsonrpc":"2.0","id":1,"result":"0x2625a0"}`))
			case data == "0x313ce567":
				_, _ = w.Write([]byte(`{"jsonrpc":"2.0","id":1,"result":"0x6"}`))
			case data == "0x95d89b41":
				_, _ = w.Write([]byte(`{"jsonrpc":"2.0","id":1,"result":"0x00000000000000000000000000000000000000000000000000000000000000204641535400000000000000000000000000000000000000000000000000000000"}`))
			default:
				_, _ = w.Write([]byte(`{"jsonrpc":"2.0","id":1,"error":{"code":-32000,"message":"unsupported call"}}`))
			}
		default:
			_, _ = w.Write([]byte(`{"jsonrpc":"2.0","id":1,"error":{"code":-32000,"message":"unsupported method"}}`))
		}
	}))
	defer server.Close()

	t.Setenv("CLAY_RPC_MONAD", server.URL)
	t.Setenv(monadScanPrimaryAPIKeyEnv, "primary")
	t.Setenv(monadScanFallbackAPIKeyEnv, "")
	monadScanAPIBase = server.URL
	client = &http.Client{Timeout: 250 * time.Millisecond}

	assets, history, err := fetchMonadFastChainData(address, 100)
	if err != nil {
		t.Fatalf("fetchMonadFastChainData returned error: %v", err)
	}
	if len(history) != 2 {
		t.Fatalf("expected 2 history rows, got %d", len(history))
	}
	if len(assets) != 2 {
		t.Fatalf("expected 2 assets, got %d", len(assets))
	}
	if assets[0].ContractAddress != "native" || assets[1].ContractAddress != token {
		t.Fatalf("unexpected assets: %+v", assets)
	}
	if history[0].ContractAddress != token && history[1].ContractAddress != token {
		t.Fatalf("expected token history row, got %+v", history)
	}
}
