package assets

import (
	"encoding/json"
	"os"
	"strings"
	"testing"
	"time"
)

type publicRPCLiveResult struct {
	Chain          string `json:"chain"`
	Address        string `json:"address"`
	AssetCount     int    `json:"asset_count"`
	HistoryCount   int    `json:"history_count"`
	FirstAsset     string `json:"first_asset,omitempty"`
	FirstHistory   string `json:"first_history,omitempty"`
	Error          string `json:"error,omitempty"`
	ElapsedMS      int64  `json:"elapsed_ms"`
	PublicEndpoint string `json:"public_endpoint,omitempty"`
}

func TestPublicRPCLiveSmoke(t *testing.T) {
	if !strings.EqualFold(strings.TrimSpace(os.Getenv("CLAY_RUN_PUBLIC_RPC_LIVE_TESTS")), "1") {
		t.Skip("set CLAY_RUN_PUBLIC_RPC_LIVE_TESTS=1 to run live public RPC probes")
	}

	t.Setenv(disableAlchemyEnv, "1")
	t.Setenv("CLAY_ASSET_CURSOR_PATH", t.TempDir()+string(os.PathSeparator)+"asset_cursors.json")

	cases := []struct {
		chain   string
		address string
	}{
		{chain: "ethereum", address: strings.TrimSpace(os.Getenv("TEST_OC_ETHEREUM"))},
		{chain: "0g", address: strings.TrimSpace(os.Getenv("TEST_OC_0G"))},
		{chain: "base", address: strings.TrimSpace(os.Getenv("TEST_OC_BASE"))},
		{chain: "bsc", address: strings.TrimSpace(os.Getenv("TEST_OC_BSC"))},
		{chain: "arbitrum", address: strings.TrimSpace(os.Getenv("TEST_OC_ARBITRUM"))},
		{chain: "monad", address: strings.TrimSpace(os.Getenv("TEST_OC_MONAD"))},
		{chain: "solana", address: strings.TrimSpace(os.Getenv("TEST_OC_SOLANA"))},
		{chain: "sui", address: strings.TrimSpace(os.Getenv("TEST_OC_SUI"))},
		{chain: "bitcoin", address: strings.TrimSpace(os.Getenv("TEST_OC_BITCOIN"))},
	}

	results := make([]publicRPCLiveResult, 0, len(cases))
	for _, tc := range cases {
		if tc.address == "" {
			continue
		}
		result := publicRPCLiveResult{
			Chain:          tc.chain,
			Address:        tc.address,
			PublicEndpoint: firstPublicRPCEndpoint(assetRPCURLs(tc.chain)),
		}
		startedAt := time.Now()

		var assets []Asset
		var history []Transaction
		var err error

		switch tc.chain {
		case "solana":
			endpoints := publicAssetRPCURLs(tc.chain)
			assets = fetchSolana(endpoints, tc.address)
			history = fetchSolanaHistory(tc.address, endpoints)
		case "sui":
			url := assetRPCURL(tc.chain)
			assets = fetchSui(url, tc.address)
			history = fetchSuiHistory(tc.address, url)
		case "bitcoin":
			assets, history, err = fetchBitcoin(tc.address)
		default:
			assets, history, err = fetchEVMChainDataWithFallback(tc.chain, assetRPCURLs(tc.chain), tc.address)
		}

		result.ElapsedMS = time.Since(startedAt).Milliseconds()
		result.AssetCount = len(assets)
		result.HistoryCount = len(history)
		if len(assets) > 0 {
			result.FirstAsset = assets[0].Symbol
		}
		if len(history) > 0 {
			result.FirstHistory = history[0].Hash
		}
		if err != nil {
			result.Error = err.Error()
			t.Errorf("%s live public rpc probe failed: %v", tc.chain, err)
		}
		results = append(results, result)
	}

	report, err := json.MarshalIndent(results, "", "  ")
	if err != nil {
		t.Fatalf("marshal live public rpc report: %v", err)
	}
	t.Logf("public_rpc_live_results=%s", string(report))
}
