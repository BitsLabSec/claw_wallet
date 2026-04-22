package assets

import (
	"os"
	"path/filepath"
	"sync"
	"testing"
	"time"
)

func TestShouldAttemptFastRefreshAfterStaleWindow(t *testing.T) {
	staleAt := time.Now().Add(-staleFastRefreshAfter - time.Minute)
	if !shouldAttemptFastRefresh("ethereum", cacheData{UpdatedAt: staleAt}) {
		t.Fatalf("expected ethereum stale cache to require fast refresh")
	}
	if shouldAttemptFastRefresh("ethereum", cacheData{}) {
		t.Fatalf("did not expect cold-start ethereum wallet to require fast refresh")
	}
	if shouldAttemptFastRefresh("ethereum", cacheData{UpdatedAt: time.Now().Add(-10 * time.Minute)}) {
		t.Fatalf("did not expect recent ethereum cache to require fast refresh")
	}
	if !shouldAttemptFastRefresh("monad", cacheData{UpdatedAt: staleAt}) {
		t.Fatalf("expected monad stale cache to require experimental fast refresh")
	}
	if !shouldAttemptFastRefresh("base", cacheData{InitializedAt: staleAt}) {
		t.Fatalf("expected long-lived unrefreshed base wallet to require fast refresh")
	}
}

func TestRecentRefreshAttemptedUsesLastTryTimestamp(t *testing.T) {
	oldCache := globalCache
	oldOnce := cacheStateOnce
	t.Cleanup(func() {
		globalCache = oldCache
		cacheStateOnce = oldOnce
	})

	globalCache = map[string]cacheData{
		"ethereum:0xabc": {
			LastRefreshTryAt: time.Now().Add(-10 * time.Second),
		},
	}
	cacheStateOnce = sync.Once{}
	t.Setenv("CLAY_ASSET_CACHE_PATH", filepath.Join(t.TempDir(), "asset_cache.json"))

	if !RecentRefreshAttempted("ethereum", "0xabc", 15*time.Second) {
		t.Fatalf("expected recent refresh attempt to be throttled")
	}
	if RecentRefreshAttempted("ethereum", "0xabc", 5*time.Second) {
		t.Fatalf("did not expect refresh attempt outside window to be throttled")
	}
}

func TestTouchWalletEntriesPersistsMetadataOnly(t *testing.T) {
	oldCache := globalCache
	oldOnce := cacheStateOnce
	oldSaveMu := cacheStateSaveMu
	t.Cleanup(func() {
		globalCache = oldCache
		cacheStateOnce = oldOnce
		cacheStateSaveMu = oldSaveMu
	})

	globalCache = make(map[string]cacheData)
	cacheStateOnce = sync.Once{}
	cacheStateSaveMu = sync.Mutex{}

	cachePath := filepath.Join(t.TempDir(), "asset_cache.json")
	t.Setenv("CLAY_ASSET_CACHE_PATH", cachePath)

	TouchWalletEntries(map[string]string{"solana": "So11111111111111111111111111111111111111112"})

	snapshot := CacheStateSnapshot()
	entry, ok := snapshot["solana:So11111111111111111111111111111111111111112"]
	if !ok {
		t.Fatalf("expected solana cache entry to be created")
	}
	if entry.InitializedAt.IsZero() {
		t.Fatalf("expected initialized timestamp to be recorded")
	}
	if entry.AssetCount != 0 || entry.HistoryCount != 0 {
		t.Fatalf("expected metadata-only init entry, got assets=%d history=%d", entry.AssetCount, entry.HistoryCount)
	}
	if _, err := os.Stat(cachePath); err != nil {
		t.Fatalf("expected persisted cache file, got %v", err)
	}
}

func TestRefreshChainCacheUsesFastPathOnProcessStartup(t *testing.T) {
	oldCache := globalCache
	oldOnce := cacheStateOnce
	oldFetch := fetchFreeChainData
	oldStartup := startupFastRefresh
	t.Cleanup(func() {
		globalCache = oldCache
		cacheStateOnce = oldOnce
		fetchFreeChainData = oldFetch
		startupFastRefresh = oldStartup
	})

	globalCache = map[string]cacheData{
		"ethereum:0xabc": {
			InitializedAt:    time.Now().Add(-5 * time.Minute),
			UpdatedAt:        time.Now(),
			HistoryUpdatedAt: time.Now(),
			WalletAddress:    "0xabc",
		},
	}
	cacheStateOnce = sync.Once{}
	startupFastRefresh = make(map[string]struct{})
	t.Setenv("CLAY_ASSET_CACHE_PATH", filepath.Join(t.TempDir(), "asset_cache.json"))
	t.Setenv("CLAY_ASSET_CURSOR_PATH", filepath.Join(t.TempDir(), "asset_cursors.json"))

	fastCalled := false
	fetchFreeChainData = func(chain, address string) ([]Asset, []Transaction, error) {
		fastCalled = true
		return []Asset{{
			Chain:           chain,
			ContractAddress: "native",
			Symbol:          "ETH",
			BalanceStr:      "1",
			Decimals:        18,
			UIBalance:       0,
		}}, nil, nil
	}

	refreshChainCache("ethereum", "0xabc", false)

	if !fastCalled {
		t.Fatalf("expected startup refresh to attempt fast path")
	}
	entry := globalCache["ethereum:0xabc"]
	if entry.LastFastRefreshAt.IsZero() {
		t.Fatalf("expected fast refresh metadata to be recorded")
	}
}

func TestRefreshChainCacheUsesFastPathWithColdCache(t *testing.T) {
	oldCache := globalCache
	oldOnce := cacheStateOnce
	oldFetch := fetchFreeChainData
	oldStartup := startupFastRefresh
	t.Cleanup(func() {
		globalCache = oldCache
		cacheStateOnce = oldOnce
		fetchFreeChainData = oldFetch
		startupFastRefresh = oldStartup
	})

	globalCache = make(map[string]cacheData)
	cacheStateOnce = sync.Once{}
	startupFastRefresh = make(map[string]struct{})
	t.Setenv("CLAY_ASSET_CACHE_PATH", filepath.Join(t.TempDir(), "asset_cache.json"))
	t.Setenv("CLAY_ASSET_CURSOR_PATH", filepath.Join(t.TempDir(), "asset_cursors.json"))

	fastCalled := false
	fetchFreeChainData = func(chain, address string) ([]Asset, []Transaction, error) {
		fastCalled = true
		return []Asset{{
			Chain:           chain,
			ContractAddress: "native",
			Symbol:          "ETH",
			BalanceStr:      "1",
			Decimals:        18,
		}}, nil, nil
	}

	refreshChainCache("ethereum", "0xdef", false)

	if !fastCalled {
		t.Fatalf("expected cold-cache refresh to attempt fast path")
	}
	entry := globalCache["ethereum:0xdef"]
	if entry.LastFastRefreshAt.IsZero() {
		t.Fatalf("expected cold-cache fast refresh metadata to be recorded")
	}
}
