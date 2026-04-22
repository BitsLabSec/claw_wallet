package assets

import (
	"encoding/json"
	"os"
	"strings"
	"sync"
	"testing"
	"time"
)

type seededPublicRPCLiveResult struct {
	Chain             string `json:"chain"`
	Address           string `json:"address"`
	FastAssetCount    int    `json:"fast_asset_count"`
	FastHistoryCount  int    `json:"fast_history_count"`
	FinalAssetCount   int    `json:"final_asset_count"`
	FinalHistoryCount int    `json:"final_history_count"`
	ElapsedMS         int64  `json:"elapsed_ms"`
	Error             string `json:"error,omitempty"`
}

func TestSeededPublicRPCRefreshLiveSmoke(t *testing.T) {
	if !strings.EqualFold(strings.TrimSpace(os.Getenv("CLAY_RUN_PUBLIC_RPC_LIVE_TESTS")), "1") {
		t.Skip("set CLAY_RUN_PUBLIC_RPC_LIVE_TESTS=1 to run seeded public RPC probes")
	}

	oldGlobalCache := globalCache
	oldCacheOnce := cacheStateOnce
	oldSlowStates := slowChainStates
	oldSlowOnce := slowChainStateOnce
	t.Cleanup(func() {
		mu.Lock()
		globalCache = oldGlobalCache
		mu.Unlock()
		cacheStateOnce = oldCacheOnce
		slowChainStates = oldSlowStates
		slowChainStateOnce = oldSlowOnce
	})

	mu.Lock()
	globalCache = make(map[string]cacheData)
	mu.Unlock()
	cacheStateOnce = sync.Once{}
	slowChainStates = make(map[string]slowChainState)
	slowChainStateOnce = sync.Once{}

	t.Setenv(disableAlchemyEnv, "1")
	t.Setenv("CLAY_ASSET_CACHE_PATH", t.TempDir()+string(os.PathSeparator)+"asset_cache.json")
	t.Setenv("CLAY_ASSET_CURSOR_PATH", t.TempDir()+string(os.PathSeparator)+"asset_cursors.json")

	cases := []struct {
		chain   string
		address string
	}{
		{chain: "ethereum", address: strings.TrimSpace(os.Getenv("TEST_OC_ETHEREUM"))},
		{chain: "base", address: strings.TrimSpace(os.Getenv("TEST_OC_BASE"))},
		{chain: "bsc", address: strings.TrimSpace(os.Getenv("TEST_OC_BSC"))},
		{chain: "arbitrum", address: strings.TrimSpace(os.Getenv("TEST_OC_ARBITRUM"))},
		{chain: "monad", address: strings.TrimSpace(os.Getenv("TEST_OC_MONAD"))},
	}

	results := make([]seededPublicRPCLiveResult, 0, len(cases))
	for _, tc := range cases {
		if tc.address == "" {
			continue
		}

		result := seededPublicRPCLiveResult{
			Chain:   tc.chain,
			Address: tc.address,
		}
		startedAt := time.Now()
		chainKey := strings.ToLower(strings.TrimSpace(tc.chain)) + ":" + strings.TrimSpace(tc.address)

		mu.Lock()
		globalCache[chainKey] = cacheData{
			InitializedAt:    time.Now().UTC().Add(-2 * staleFastRefreshAfter),
			UpdatedAt:        time.Now().UTC().Add(-2 * staleFastRefreshAfter),
			HistoryUpdatedAt: time.Now().UTC().Add(-2 * staleFastRefreshAfter),
			WalletAddress:    tc.address,
		}
		mu.Unlock()

		fastAssets, fastHistory, ok := tryFastRefresh(tc.chain, tc.address, chainKey)
		result.FastAssetCount = len(fastAssets)
		result.FastHistoryCount = len(fastHistory)
		if !ok {
			result.Error = "fast refresh unavailable"
			results = append(results, result)
			t.Errorf("%s seeded public rpc probe failed: fast refresh unavailable", tc.chain)
			continue
		}

		refreshChainCache(tc.chain, tc.address, true)

		mu.RLock()
		entry := globalCache[chainKey]
		mu.RUnlock()
		result.FinalAssetCount = len(entry.Assets)
		result.FinalHistoryCount = len(entry.History)
		result.ElapsedMS = time.Since(startedAt).Milliseconds()
		results = append(results, result)
	}

	report, err := json.MarshalIndent(results, "", "  ")
	if err != nil {
		t.Fatalf("marshal seeded public rpc report: %v", err)
	}
	t.Logf("seeded_public_rpc_live_results=%s", string(report))
}
