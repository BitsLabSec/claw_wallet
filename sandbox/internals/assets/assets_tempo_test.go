package assets

import (
	"encoding/hex"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
)

func TestTempoAssetConfig(t *testing.T) {
	if got := defaultDecimalsForChain("tempo"); got != 18 {
		t.Fatalf("defaultDecimalsForChain(tempo) = %d, want 18", got)
	}
	if got := assetRPCURL("tempo"); got != "https://rpc.moderato.tempo.xyz" {
		t.Fatalf("assetRPCURL(tempo) = %q", got)
	}
	urls := assetRPCURLs("tempo")
	if len(urls) != 1 {
		t.Fatalf("expected only public tempo rpc list, got %v", urls)
	}
	if urls[0] != "https://rpc.moderato.tempo.xyz" {
		t.Fatalf("expected public tempo rpc first, got %v", urls)
	}
	if got := alchemyRPCURL("tempo"); got != "" {
		t.Fatalf("expected tempo alchemy endpoint to come only from env, got %q", got)
	}
	if got := getNativeSymbol("tempo"); got != "USD" {
		t.Fatalf("getNativeSymbol(tempo) = %q, want USD", got)
	}
	if got := ExplorerAddressURL("tempo", "0x123"); got != "https://explore.tempo.xyz/address/0x123" {
		t.Fatalf("ExplorerAddressURL(tempo) = %q", got)
	}
	if got := ExplorerTxURL("tempo", "0xabc"); got != "https://explore.tempo.xyz/tx/0xabc" {
		t.Fatalf("ExplorerTxURL(tempo) = %q", got)
	}
	if got := ExplorerTokenURL("tempo", "0xtoken"); got != "https://explore.tempo.xyz/token/0xtoken" {
		t.Fatalf("ExplorerTokenURL(tempo) = %q", got)
	}
	if !containsString(evmRefreshChains, "tempo") {
		t.Fatalf("evmRefreshChains missing tempo: %v", evmRefreshChains)
	}
	if !supportsFastRefresh("tempo") {
		t.Fatalf("expected tempo to support fast refresh")
	}
}

func TestTempoSuppressesNativeBalanceDisplay(t *testing.T) {
	if !suppressNativeBalanceDisplay("tempo") {
		t.Fatalf("expected tempo native balance display to be suppressed")
	}
	if suppressNativeBalanceDisplay("ethereum") {
		t.Fatalf("did not expect ethereum native balance display to be suppressed")
	}
}

func TestTempoAlchemyPreferredForAssetAndRPCProxyURLs(t *testing.T) {
	t.Setenv("CLAY_ALCHEMY_RPC_TEMPO", "https://tempo-moderato.g.alchemy.com/v2/test-key")
	t.Setenv("CLAY_RPC_TEMPO", "")

	assetURLs := assetRPCURLs("tempo")
	if len(assetURLs) != 1 {
		t.Fatalf("expected tempo asset rpc urls to stay public-only, got %v", assetURLs)
	}
	if assetURLs[0] != "https://rpc.moderato.tempo.xyz" {
		t.Fatalf("expected public tempo asset rpc first, got %v", assetURLs)
	}

	proxyURLs := RPCProxyURLs("tempo")
	if len(proxyURLs) < 2 {
		t.Fatalf("expected tempo rpc proxy urls to include alchemy and public fallback, got %v", proxyURLs)
	}
	if proxyURLs[0] != "https://rpc.moderato.tempo.xyz" {
		t.Fatalf("expected public tempo rpc proxy first, got %v", proxyURLs)
	}
	if proxyURLs[len(proxyURLs)-1] != "https://tempo-moderato.g.alchemy.com/v2/test-key" {
		t.Fatalf("expected tempo alchemy fallback last for proxy, got %v", proxyURLs)
	}
}

func TestTempoFastRPCURLsPreferAlchemy(t *testing.T) {
	t.Setenv("CLAY_ALCHEMY_RPC_TEMPO", "https://tempo-moderato.g.alchemy.com/v2/test-key")
	t.Setenv("CLAY_RPC_TEMPO", "")

	urls := tempoFastRPCURLs()
	if len(urls) < 2 {
		t.Fatalf("expected tempo fast rpc urls to include alchemy and public fallback, got %v", urls)
	}
	if urls[0] != "https://tempo-moderato.g.alchemy.com/v2/test-key" {
		t.Fatalf("expected tempo fast rpc to prefer alchemy first, got %v", urls)
	}
	if urls[1] != "https://rpc.moderato.tempo.xyz" {
		t.Fatalf("expected tempo public fallback second for fast rpc, got %v", urls)
	}
}

func TestTryFastRefreshAcceptsEmptyTempoWallet(t *testing.T) {
	oldCache := globalCache
	oldOnce := cacheStateOnce
	oldFetch := fetchFreeChainData
	t.Cleanup(func() {
		globalCache = oldCache
		cacheStateOnce = oldOnce
		fetchFreeChainData = oldFetch
	})

	globalCache = make(map[string]cacheData)
	cacheStateOnce = sync.Once{}
	t.Setenv("CLAY_ASSET_CACHE_PATH", t.TempDir()+"\\asset_cache.json")

	fetchFreeChainData = func(chain, address string) ([]Asset, []Transaction, error) {
		if chain != "tempo" {
			t.Fatalf("unexpected chain %q", chain)
		}
		return nil, nil, nil
	}

	if _, _, ok := tryFastRefresh("tempo", "0xabc", "tempo:0xabc"); !ok {
		t.Fatalf("expected empty tempo fast refresh result to be accepted")
	}
	entry := globalCache["tempo:0xabc"]
	if entry.LastFastRefreshAt.IsZero() {
		t.Fatalf("expected fast refresh metadata to be recorded for empty tempo wallet")
	}
}

func TestFetchHistoryOnlyWithFallbackSupportsTempo(t *testing.T) {
	const address = "0x5ee63739549d32bcdce25344e352afc640e44c2d"

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		serveTestJSONRPC(t, w, r, func(req testJSONRPCRequest) testJSONRPCResponse {
			switch req.Method {
			case "eth_blockNumber":
				return testJSONRPCResponse{JSONRPC: "2.0", ID: req.ID, Result: "0x10"}
			case "eth_getTransactionCount":
				return testJSONRPCResponse{JSONRPC: "2.0", ID: req.ID, Result: "0x0"}
			case "eth_getBlockByNumber":
				return testJSONRPCResponse{JSONRPC: "2.0", ID: req.ID, Result: map[string]any{
					"timestamp":    "0x6566e100",
					"transactions": []any{},
				}}
			case "eth_getLogs":
				return testJSONRPCResponse{JSONRPC: "2.0", ID: req.ID, Result: []any{}}
			default:
				t.Fatalf("unexpected method %s", req.Method)
				return testJSONRPCResponse{}
			}
		})
	}))
	defer server.Close()
	t.Setenv("CLAY_RPC_TEMPO", server.URL)

	history, err := fetchHistoryOnlyWithFallback("tempo", address, 5)
	if err != nil {
		t.Fatalf("fetchHistoryOnlyWithFallback(tempo) returned error: %v", err)
	}
	if len(history) != 0 {
		t.Fatalf("expected empty tempo history, got %+v", history)
	}
}

func TestFetchEVMChainDataWithFallbackUsesTempoTIP20Assets(t *testing.T) {
	const address = "0x5ee63739549d32bcdce25344e352afc640e44c2d"
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		serveTestJSONRPC(t, w, r, func(req testJSONRPCRequest) testJSONRPCResponse {
			switch req.Method {
			case "eth_call":
				params := req.Params
				call, _ := params[0].(map[string]any)
				data := stringValue(call["data"])
				to := strings.ToLower(stringValue(call["to"]))
				switch data {
				case "0x313ce567":
					return testJSONRPCResponse{JSONRPC: "2.0", ID: req.ID, Result: "0x0000000000000000000000000000000000000000000000000000000000000012"}
				case "0x95d89b41":
					if to == strings.ToLower(tempoPathUSD) {
						return testJSONRPCResponse{JSONRPC: "2.0", ID: req.ID, Result: tempoTestABIStringResult("pathUSD")}
					}
					return testJSONRPCResponse{JSONRPC: "2.0", ID: req.ID, Result: tempoTestABIStringResult("USDCe")}
				default:
					if strings.HasPrefix(data, "0x70a08231") {
						if to == strings.ToLower(tempoPathUSD) {
							return testJSONRPCResponse{JSONRPC: "2.0", ID: req.ID, Result: "0x00000000000000000000000000000000000000000000000000000000000003e8"}
						}
						return testJSONRPCResponse{JSONRPC: "2.0", ID: req.ID, Result: "0x0"}
					}
					t.Fatalf("unexpected eth_call data %s", data)
					return testJSONRPCResponse{}
				}
			case "eth_blockNumber":
				return testJSONRPCResponse{JSONRPC: "2.0", ID: req.ID, Result: "0x10"}
			case "eth_getTransactionCount":
				return testJSONRPCResponse{JSONRPC: "2.0", ID: req.ID, Result: "0x0"}
			case "eth_getBlockByNumber":
				return testJSONRPCResponse{JSONRPC: "2.0", ID: req.ID, Result: map[string]any{
					"timestamp":    "0x6566e100",
					"transactions": []any{},
				}}
			case "eth_getLogs":
				return testJSONRPCResponse{JSONRPC: "2.0", ID: req.ID, Result: []any{}}
			case "alchemy_getTokenBalances", "alchemy_getAssetTransfers", "alchemy_getTokenMetadata":
				t.Fatalf("tempo fallback should not call %s", req.Method)
				return testJSONRPCResponse{}
			default:
				t.Fatalf("unexpected method %s", req.Method)
				return testJSONRPCResponse{}
			}
		})
	}))
	defer server.Close()
	t.Setenv("CLAY_RPC_TEMPO", server.URL)
	endpoints := assetRPCURLs("tempo")

	assets, history, err := fetchEVMChainDataWithFallback("tempo", endpoints, address)
	if err != nil {
		t.Fatalf("fetchEVMChainDataWithFallback(tempo) returned error: %v", err)
	}
	if len(assets) != 1 {
		t.Fatalf("expected exactly one tempo asset, got %+v", assets)
	}
	if assets[0].ContractAddress != tempoPathUSD {
		t.Fatalf("expected tempo asset %s, got %+v", tempoPathUSD, assets[0])
	}
	if assets[0].Symbol != "pathUSD" {
		t.Fatalf("expected tempo symbol pathUSD, got %+v", assets[0])
	}
	if len(history) != 0 {
		t.Fatalf("expected empty tempo history, got %+v", history)
	}
}

func tempoTestABIStringResult(value string) string {
	return "0x" + hex.EncodeToString([]byte(value)) + strings.Repeat("0", 64-len(value)*2)
}
