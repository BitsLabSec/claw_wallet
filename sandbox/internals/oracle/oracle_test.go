package oracle

import (
	"errors"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"
)

func TestRestoreForTestSeedsNativePricesAndHealthy(t *testing.T) {
	RestoreForTest(map[string]float64{
		"native:ethereum": 3000,
		"native:bsc":      600,
		"native:monad":    9.5,
		"native:tron":     0.12,
		"token:bsc:0xabc": 1.25,
	})

	if !IsHealthy() {
		t.Fatal("expected oracle to be healthy after RestoreForTest")
	}

	if price, ok := Get("ethereum"); !ok || price != 3000 {
		t.Fatalf("expected ethereum price 3000, got %v ok=%v", price, ok)
	}
	if price, ok := Get("bsc"); !ok || price != 600 {
		t.Fatalf("expected bsc price 600, got %v ok=%v", price, ok)
	}
	if price, ok := Get("monad"); !ok || price != 9.5 {
		t.Fatalf("expected monad price 9.5, got %v ok=%v", price, ok)
	}
	if price, ok := Get("tron"); !ok || price != 0.12 {
		t.Fatalf("expected tron price 0.12, got %v ok=%v", price, ok)
	}
	if price, ok := GetToken("bsc", "0xabc", "ABC"); !ok || price != 1.25 {
		t.Fatalf("expected token price 1.25, got %v ok=%v", price, ok)
	}
}

func TestSnapshotIncludesNativeAndTokenEntries(t *testing.T) {
	RestoreForTest(map[string]float64{
		"native:solana":           150,
		"native:monad":            8.25,
		"native:tron":             0.11,
		"token:solana:MintBase58": 2.5,
	})

	snapshot := Snapshot()
	if snapshot["native:solana"] != 150 {
		t.Fatalf("expected native:solana=150, got %v", snapshot["native:solana"])
	}
	if snapshot["native:monad"] != 8.25 {
		t.Fatalf("expected native:monad=8.25, got %v", snapshot["native:monad"])
	}
	if snapshot["native:tron"] != 0.11 {
		t.Fatalf("expected native:tron=0.11, got %v", snapshot["native:tron"])
	}
	if snapshot["token:solana:MintBase58"] != 2.5 {
		t.Fatalf("expected token:solana:MintBase58=2.5, got %v", snapshot["token:solana:MintBase58"])
	}
}

func TestGetUsesFreshCachedValueWithoutRefresh(t *testing.T) {
	o := &Oracle{
		cache: map[string]PriceEntry{
			"ethereum": {USD: 3210.5, FetchedAt: time.Now()},
		},
		tokenCache: map[string]PriceEntry{},
		healthy:    true,
	}

	price, ok := o.Get("ethereum")
	if !ok {
		t.Fatal("expected fresh cached ethereum price to be usable")
	}
	if price != 3210.5 {
		t.Fatalf("expected 3210.5, got %v", price)
	}
}

func TestGetTokenUsesFreshCachedValueWithoutFetch(t *testing.T) {
	o := &Oracle{
		cache: map[string]PriceEntry{},
		tokenCache: map[string]PriceEntry{
			"bsc:0xabc": {USD: 0.99, FetchedAt: time.Now()},
		},
		healthy: true,
	}

	price, ok := o.GetToken("bsc", "0xabc", "USDT")
	if !ok {
		t.Fatal("expected fresh cached token price to be usable")
	}
	if price != 0.99 {
		t.Fatalf("expected 0.99, got %v", price)
	}
}

func TestGetFetchesOnlyRequestedNativeChainOnDemand(t *testing.T) {
	oldNativeFetcher := coinGeckoNativeFetcher
	oldBackendFetcher := backendPriceFetcher
	defer func() {
		coinGeckoNativeFetcher = oldNativeFetcher
		backendPriceFetcher = oldBackendFetcher
	}()

	called := make([]string, 0, 2)
	coinGeckoNativeFetcher = func(chain string) (float64, error) {
		called = append(called, chain)
		return 2049.44, nil
	}
	backendPriceFetcher = func(chain, contract, symbol string) (float64, error) {
		t.Fatalf("backend fallback should not run when primary succeeds")
		return 0, nil
	}

	o := &Oracle{
		cache:      map[string]PriceEntry{},
		tokenCache: map[string]PriceEntry{},
	}

	price, ok := o.Get("ethereum")
	if !ok || price != 2049.44 {
		t.Fatalf("expected live ethereum price, got %v ok=%v", price, ok)
	}
	if len(called) != 1 || called[0] != "ethereum" {
		t.Fatalf("expected single-asset native fetch for ethereum, got %+v", called)
	}
}

func TestGetTokenFallsBackToBackendAndCachesResult(t *testing.T) {
	oldDexFetcher := dexScreenerPriceFetcher
	oldTokenFetcher := coinGeckoTokenFetcher
	oldBackendFetcher := backendPriceFetcher
	defer func() {
		dexScreenerPriceFetcher = oldDexFetcher
		coinGeckoTokenFetcher = oldTokenFetcher
		backendPriceFetcher = oldBackendFetcher
	}()

	dexScreenerPriceFetcher = func(chain, contract string) (float64, error) {
		return 0, errors.New("dex timeout")
	}
	coinGeckoTokenFetcher = func(chain, contract string) (float64, error) {
		return 0, errors.New("coingecko timeout")
	}
	backendPriceFetcher = func(chain, contract, symbol string) (float64, error) {
		if chain != "bsc" || contract != "0xabc" || symbol != "USDT" {
			t.Fatalf("unexpected backend fallback args: %s %s %s", chain, contract, symbol)
		}
		return 1.01, nil
	}

	o := &Oracle{
		cache:      map[string]PriceEntry{},
		tokenCache: map[string]PriceEntry{},
	}

	price, ok := o.GetToken("bsc", "0xabc", "USDT")
	if !ok || price != 1.01 {
		t.Fatalf("expected backend fallback token price, got %v ok=%v", price, ok)
	}

	cached, ok := o.tokenCache["bsc:0xabc"]
	if !ok || cached.USD != 1.01 {
		t.Fatalf("expected backend fallback result to be cached, got %+v ok=%v", cached, ok)
	}
}

func TestGetTokenUsesStaleCacheWhenLiveFetchFails(t *testing.T) {
	oldDexFetcher := dexScreenerPriceFetcher
	oldTokenFetcher := coinGeckoTokenFetcher
	oldBackendFetcher := backendPriceFetcher
	defer func() {
		dexScreenerPriceFetcher = oldDexFetcher
		coinGeckoTokenFetcher = oldTokenFetcher
		backendPriceFetcher = oldBackendFetcher
	}()

	dexScreenerPriceFetcher = func(chain, contract string) (float64, error) {
		return 0, errors.New("dex timeout")
	}
	coinGeckoTokenFetcher = func(chain, contract string) (float64, error) {
		return 0, errors.New("coingecko timeout")
	}
	backendPriceFetcher = func(chain, contract, symbol string) (float64, error) {
		return 0, errors.New("backend timeout")
	}

	o := &Oracle{
		cache: map[string]PriceEntry{},
		tokenCache: map[string]PriceEntry{
			"solana:MintBase58": {USD: 2.25, FetchedAt: time.Now().Add(-10 * time.Minute)},
		},
	}

	price, ok := o.GetToken("solana", "MintBase58", "USDC")
	if !ok || price != 2.25 {
		t.Fatalf("expected stale cached token price, got %v ok=%v", price, ok)
	}
}

func TestAPITimeoutIsThreeSeconds(t *testing.T) {
	if apiTimeout != 3*time.Second {
		t.Fatalf("apiTimeout = %s, want 3s", apiTimeout)
	}
}

func TestFetchNativePriceFallsBackAfterPrimaryTimeout(t *testing.T) {
	oldNativeFetcher := coinGeckoNativeFetcher
	oldBackendFetcher := backendPriceFetcher
	defer func() {
		coinGeckoNativeFetcher = oldNativeFetcher
		backendPriceFetcher = oldBackendFetcher
	}()

	slowServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		time.Sleep(3500 * time.Millisecond)
		w.Header().Set("Content-Type", "application/json")
		w.Write([]byte(`{"ethereum":{"usd":2049.44}}`))
	}))
	defer slowServer.Close()

	coinGeckoNativeFetcher = func(chain string) (float64, error) {
		var raw map[string]map[string]float64
		if err := httpGetJSONWithTimeout(slowServer.URL, &raw); err != nil {
			return 0, err
		}
		return raw["ethereum"]["usd"], nil
	}
	backendPriceFetcher = func(chain, contract, symbol string) (float64, error) {
		return 2050, nil
	}

	started := time.Now()
	price, err := fetchNativePrice("ethereum")
	elapsed := time.Since(started)

	if err != nil {
		t.Fatalf("expected backend fallback after timeout, got %v", err)
	}
	if price != 2050 {
		t.Fatalf("expected backend fallback price 2050, got %v", price)
	}
	if elapsed < 2900*time.Millisecond || elapsed > 3800*time.Millisecond {
		t.Fatalf("expected fallback around 3s timeout, got %s", elapsed)
	}
}

func TestRefreshFallsBackForMissingBatchNativePrices(t *testing.T) {
	oldNativeFetcher := coinGeckoNativeFetcher
	oldBackendFetcher := backendPriceFetcher
	defer func() {
		coinGeckoNativeFetcher = oldNativeFetcher
		backendPriceFetcher = oldBackendFetcher
	}()

	called := make([]string, 0, 4)
	coinGeckoNativeFetcher = func(chain string) (float64, error) {
		called = append(called, "cg:"+chain)
		switch chain {
		case "kite":
			return 0.13, nil
		default:
			return 0, errors.New("forced CoinGecko miss")
		}
	}
	backendPriceFetcher = func(chain, contract, symbol string) (float64, error) {
		called = append(called, "backend:"+chain)
		return 1, nil
	}

	o := &Oracle{
		cache: map[string]PriceEntry{
			"ethereum": {USD: 2000, FetchedAt: time.Now().Add(-time.Hour)},
		},
		tokenCache: map[string]PriceEntry{},
	}

	updated, err := o.refreshNativePricesFromBatch(map[string]map[string]float64{
		"ethereum": {"usd": 2100},
	})
	if err != nil {
		t.Fatalf("refreshNativePricesFromBatch returned error: %v", err)
	}
	if updated < 2 {
		t.Fatalf("expected batch refresh + fallback updates, got %d", updated)
	}

	kite, ok := o.cache["kite-2"]
	if !ok || kite.USD != 0.13 {
		t.Fatalf("expected kite native fallback price to be stored, got %+v ok=%v", kite, ok)
	}
	if len(called) == 0 {
		t.Fatal("expected native fallback fetchers to be exercised")
	}
}
