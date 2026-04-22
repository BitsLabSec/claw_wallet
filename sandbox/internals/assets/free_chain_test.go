package assets

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"sync/atomic"
	"testing"
	"time"

	"sandbox/pkg/bitcoinesplora"
)

func TestFetchFreeChainDataTempoUsesStandardRPCFastPath(t *testing.T) {
	const address = "0xabc0000000000000000000000000000000000001"
	t.Setenv(disableAlchemyEnv, "1")
	t.Setenv("CLAY_RPC_TEMPO", "")

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		serveTestJSONRPC(t, w, r, func(req testJSONRPCRequest) testJSONRPCResponse {
			switch req.Method {
			case "eth_getBalance", "eth_blockNumber", "eth_getTransactionCount", "eth_getBlockByNumber", "eth_getLogs":
				t.Fatalf("tempo fast path should stay lightweight for empty wallets and not call %s", req.Method)
				return testJSONRPCResponse{}
			case "alchemy_getTokenBalances", "alchemy_getAssetTransfers", "alchemy_getTokenMetadata":
				t.Fatalf("tempo fast path should not call %s", req.Method)
				return testJSONRPCResponse{}
			default:
				t.Fatalf("unexpected method %s", req.Method)
				return testJSONRPCResponse{}
			}
		})
	}))
	defer server.Close()

	t.Setenv("CLAY_RPC_TEMPO", server.URL)

	assets, history, err := FetchFreeChainData("tempo", address)
	if err != nil {
		t.Fatalf("FetchFreeChainData(tempo) returned error: %v", err)
	}
	if len(assets) != 0 {
		t.Fatalf("expected empty tempo assets for native-suppressed zero-balance wallet, got %+v", assets)
	}
	if len(history) != 0 {
		t.Fatalf("expected empty tempo history, got %+v", history)
	}
}

func TestFetchBitcoinAddressInfoTriesAllConfiguredBases(t *testing.T) {
	const address = "bc1qexample"

	bitcoinesplora.SetBasesForTest(nil)
	t.Cleanup(func() {
		bitcoinesplora.SetBasesForTest(nil)
	})

	down1 := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusTooManyRequests)
		_, _ = w.Write([]byte(`{"error":"rate limited"}`))
	}))
	defer down1.Close()

	down2 := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusBadGateway)
		_, _ = w.Write([]byte(`{"error":"upstream unavailable"}`))
	}))
	defer down2.Close()

	ok := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"chain_stats":{"funded_txo_sum":210000000,"spent_txo_sum":100000000},"mempool_stats":{"funded_txo_sum":0,"spent_txo_sum":0}}`))
	}))
	defer ok.Close()

	bitcoinesplora.SetBasesForTest([]string{down1.URL, down2.URL, ok.URL})

	info, baseURL, err := fetchBitcoinAddressInfo(address, time.Now().Add(3*time.Second))
	if err != nil {
		t.Fatalf("fetchBitcoinAddressInfo returned error: %v", err)
	}
	if baseURL != ok.URL {
		t.Fatalf("expected fallback to final base %q, got %q", ok.URL, baseURL)
	}
	if info.ChainStats.FundedTXOSum != 210000000 || info.ChainStats.SpentTXOSum != 100000000 {
		t.Fatalf("unexpected info: %+v", info)
	}
}

func TestFetchBlockscoutChainParsesAssetsAndHistory(t *testing.T) {
	const address = "0xabc"
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		switch r.URL.Path {
		case "/addresses/" + address:
			_, _ = w.Write([]byte(`{"coin_balance":"1000000000000000000"}`))
		case "/addresses/" + address + "/token-balances":
			_, _ = w.Write([]byte(`[{"value":"2500000","token":{"type":"ERC-20","address_hash":"0xtoken","symbol":"USDC","decimals":"6"}}]`))
		case "/addresses/" + address + "/transactions":
			_, _ = w.Write([]byte(`{"items":[{"hash":"0xhash1","from":{"hash":"0xabc"},"to":{"hash":"0xdef"},"value":"100000000000000000","status":"ok","timestamp":"2026-04-03T10:00:00Z"}]}`))
		case "/addresses/" + address + "/token-transfers":
			_, _ = w.Write([]byte(`{"items":[{"transaction_hash":"0xhash2","from":{"hash":"0xdef"},"to":{"hash":"0xabc"},"total":"1250000","timestamp":"2026-04-03T10:01:00Z","token":{"address_hash":"0xtoken","symbol":"USDC","decimals":"6"}}]}`))
		default:
			http.NotFound(w, r)
		}
	}))
	defer srv.Close()

	assets, history, err := fetchBlockscoutChain("base", srv.URL, address)
	if err != nil {
		t.Fatalf("fetchBlockscoutChain returned error: %v", err)
	}
	if len(assets) != 2 {
		t.Fatalf("expected 2 assets, got %d", len(assets))
	}
	if len(history) != 2 {
		t.Fatalf("expected 2 history rows, got %d", len(history))
	}
}

func TestFetchEthplorerChainParsesAssetsAndHistory(t *testing.T) {
	const address = "0xabc"
	t.Setenv("ETHPLORER_API_KEY", "test-ethplorer-key")
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		switch {
		case r.URL.Path == "/getAddressInfo/"+address:
			_, _ = w.Write([]byte(`{"BNB":{"rawBalance":"1000000000000000000"},"tokens":[{"rawBalance":"4200000","tokenInfo":{"address":"0xtoken","symbol":"BUSD","decimals":"6"}}]}`))
		case r.URL.Path == "/getAddressTransactions/"+address:
			_, _ = w.Write([]byte(`{"operations":[{"transactionHash":"0xhash1","from":"0xabc","to":"0xdef","value":"100000000000000000","timestamp":"2026-04-03T10:00:00Z","success":"true"}]}`))
		case r.URL.Path == "/getAddressHistory/"+address:
			_, _ = w.Write([]byte(`{"operations":[{"transactionHash":"0xhash2","from":"0xdef","to":"0xabc","value":"1250000","timestamp":"2026-04-03T10:01:00Z","tokenInfo":{"address":"0xtoken","symbol":"BUSD","decimals":"6"},"success":"true"}]}`))
		default:
			http.NotFound(w, r)
		}
	}))
	defer srv.Close()

	baseURL := srv.URL
	assets, history, err := fetchEthplorerChain("bsc", baseURL, address)
	if err != nil {
		t.Fatalf("fetchEthplorerChain returned error: %v", err)
	}
	if len(assets) != 2 {
		t.Fatalf("expected 2 assets, got %d", len(assets))
	}
	if len(history) != 2 {
		t.Fatalf("expected 2 history rows, got %d", len(history))
	}
	if history[0].Hash == "" && history[1].Hash == "" {
		t.Fatalf("expected parsed history hashes, got %+v", history)
	}
}

func TestGetJSONWithClientRetriesRateLimitedResponses(t *testing.T) {
	var attempts int32
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		n := atomic.AddInt32(&attempts, 1)
		w.Header().Set("Content-Type", "application/json")
		if n < 3 {
			w.WriteHeader(http.StatusTooManyRequests)
			_, _ = w.Write([]byte(`{"error":"rate limited"}`))
			return
		}
		_ = json.NewEncoder(w).Encode(map[string]string{"ok": "true"})
	}))
	defer srv.Close()

	var payload map[string]string
	if err := getJSONWithClient(client, srv.URL, &payload); err != nil {
		t.Fatalf("expected retrying GET to succeed, got %v", err)
	}
	if payload["ok"] != "true" {
		t.Fatalf("unexpected payload: %+v", payload)
	}
	if got := atomic.LoadInt32(&attempts); got != 3 {
		t.Fatalf("expected 3 attempts, got %d", got)
	}
}
