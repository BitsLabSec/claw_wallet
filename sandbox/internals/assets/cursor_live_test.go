package assets

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"
)

type publicRPCCursorWarmResult struct {
	Chain             string `json:"chain"`
	Address           string `json:"address"`
	ColdAssetCount    int    `json:"cold_asset_count"`
	ColdHistoryCount  int    `json:"cold_history_count"`
	ColdElapsedMS     int64  `json:"cold_elapsed_ms"`
	WarmAssetCount    int    `json:"warm_asset_count"`
	WarmHistoryCount  int    `json:"warm_history_count"`
	WarmElapsedMS     int64  `json:"warm_elapsed_ms"`
	ColdFirstHistory  string `json:"cold_first_history,omitempty"`
	WarmFirstHistory  string `json:"warm_first_history,omitempty"`
	PublicEndpoint    string `json:"public_endpoint,omitempty"`
	Error             string `json:"error,omitempty"`
}

func TestPurePublicRPCCursorWarmLiveSmoke(t *testing.T) {
	if !strings.EqualFold(strings.TrimSpace(os.Getenv("CLAY_RUN_PUBLIC_RPC_CURSOR_LIVE_TESTS")), "1") {
		t.Skip("set CLAY_RUN_PUBLIC_RPC_CURSOR_LIVE_TESTS=1 to run public RPC cursor warm probes")
	}

	oldGlobalCache := globalCache
	oldCacheOnce := cacheStateOnce
	oldSlowStates := slowChainStates
	oldSlowRefreshing := slowChainRefreshing
	oldSlowDone := slowChainRefreshDone
	oldSlowOnce := slowChainStateOnce
	t.Cleanup(func() {
		mu.Lock()
		globalCache = oldGlobalCache
		mu.Unlock()
		cacheStateOnce = oldCacheOnce

		slowChainMu.Lock()
		slowChainStates = oldSlowStates
		slowChainRefreshing = oldSlowRefreshing
		slowChainRefreshDone = oldSlowDone
		slowChainMu.Unlock()
		slowChainStateOnce = oldSlowOnce
	})

	t.Setenv(disableAlchemyEnv, "1")
	t.Setenv(disableExplorerFallbackEnv, "1")
	dir := t.TempDir()
	t.Setenv("CLAY_ASSET_CACHE_PATH", filepath.Join(dir, "asset_cache.json"))
	t.Setenv("CLAY_ASSET_CURSOR_PATH", filepath.Join(dir, "asset_cursors.json"))

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
	}

	results := make([]publicRPCCursorWarmResult, 0, len(cases))
	for _, tc := range cases {
		if tc.address == "" {
			continue
		}

		result := publicRPCCursorWarmResult{
			Chain:          tc.chain,
			Address:        tc.address,
			PublicEndpoint: firstPublicRPCEndpoint(assetRPCURLs(tc.chain)),
		}

		resetCursorWarmLiveState()
		coldStartedAt := time.Now()
		refreshChainCache(tc.chain, tc.address, true)
		result.ColdElapsedMS = time.Since(coldStartedAt).Milliseconds()
		coldEntry := Snapshot()[strings.ToLower(strings.TrimSpace(tc.chain))+":"+strings.TrimSpace(tc.address)]
		result.ColdAssetCount = len(coldEntry.Assets)
		result.ColdHistoryCount = len(coldEntry.History)
		if len(coldEntry.History) > 0 {
			result.ColdFirstHistory = coldEntry.History[0].Hash
		}
		if result.ColdAssetCount == 0 && result.ColdHistoryCount == 0 {
			result.Error = "cold refresh returned empty cache entry"
			results = append(results, result)
			t.Errorf("%s cold cursor probe failed: empty cache entry", tc.chain)
			continue
		}

		resetCursorWarmLiveState()
		warmStartedAt := time.Now()
		refreshChainCache(tc.chain, tc.address, true)
		result.WarmElapsedMS = time.Since(warmStartedAt).Milliseconds()
		warmEntry := Snapshot()[strings.ToLower(strings.TrimSpace(tc.chain))+":"+strings.TrimSpace(tc.address)]
		result.WarmAssetCount = len(warmEntry.Assets)
		result.WarmHistoryCount = len(warmEntry.History)
		if len(warmEntry.History) > 0 {
			result.WarmFirstHistory = warmEntry.History[0].Hash
		}
		if result.WarmAssetCount == 0 && result.WarmHistoryCount == 0 {
			result.Error = "warm refresh returned empty cache entry"
			t.Errorf("%s warm cursor probe failed: empty cache entry", tc.chain)
		}
		results = append(results, result)
	}

	report, err := json.MarshalIndent(results, "", "  ")
	if err != nil {
		t.Fatalf("marshal public rpc cursor warm report: %v", err)
	}
	t.Logf("public_rpc_cursor_warm_results=%s", string(report))
}

func resetCursorWarmLiveState() {
	mu.Lock()
	globalCache = make(map[string]cacheData)
	mu.Unlock()
	cacheStateOnce = sync.Once{}

	slowChainMu.Lock()
	slowChainStates = make(map[string]slowChainState)
	slowChainRefreshing = make(map[string]time.Time)
	slowChainRefreshDone = make(map[string]chan struct{})
	slowChainMu.Unlock()
	slowChainStateOnce = sync.Once{}
}
