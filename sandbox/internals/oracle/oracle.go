// sandbox/internals/oracle/oracle.go
// In-process Price Oracle backed by CoinGecko, DexScreener, and backend fallback.
// Maintains a local price cache (TTL: 5 min) for all chains supported by the sandbox.
// Failure mode: if all sources fail, returns (0, false) and callers decide whether to block.
package oracle

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"net/http"
	"net/url"
	"os"
	"strconv"
	"strings"
	"sync"
	"time"
)

const (
	cacheTTL    = 5 * time.Minute
	maxStaleTTL = 30 * time.Minute // Block if over 30 mins stale
	apiTimeout  = 3 * time.Second

	// CoinGecko IDs for native tokens of each chain we support.
	geckoBase = "https://api.coingecko.com/api/v3/simple/price?vs_currencies=usd&ids="
)

// chainGeckoID maps our internal chain name to CoinGecko coin ID.
var chainGeckoID = map[string]string{
	"ethereum": "ethereum",
	"0g":       "zero-gravity",
	"arbitrum": "ethereum",
	"base":     "ethereum",
	"bsc":      "binancecoin",
	"monad":    "monad",
	"kite":     "kite-2",
	"tron":     "tron",
	"solana":   "solana",
	"sui":      "sui",
	"bitcoin":  "bitcoin",
}

// chainCoinGeckoPlatform maps our chain name to CoinGecko token-price platform IDs.
var chainCoinGeckoPlatform = map[string]string{
	"ethereum": "ethereum",
	"base":     "base",
	"bsc":      "binance-smart-chain",
	"arbitrum": "arbitrum-one",
	"monad":    "monad",
	"solana":   "solana",
	"sui":      "sui",
}

// PriceEntry holds a cached USD price.
type PriceEntry struct {
	USD       float64
	FetchedAt time.Time
}

// Oracle manages a thread-safe local price cache.
type Oracle struct {
	mu         sync.RWMutex
	cache      map[string]PriceEntry // key = coingecko coin ID
	tokenCache map[string]PriceEntry // key = "chain:contract"
	healthy    bool
	forcedDown bool
	refreshing bool
	lastError  string
	lastTryAt  time.Time
	lastOKAt   time.Time
}

type StatusSnapshot struct {
	Healthy            bool
	ForcedUnavailable  bool
	LastRefreshAttempt time.Time
	LastRefreshSuccess time.Time
	LastRefreshError   string
	NativeStaleFor     time.Duration
}

var defaultOracle = &Oracle{
	cache:      make(map[string]PriceEntry),
	tokenCache: make(map[string]PriceEntry),
	healthy:    false,
}

var autoRefreshOnce sync.Once

var (
	dexScreenerPriceFetcher = fetchDexScreener
	coinGeckoNativeFetcher  = fetchCoinGeckoNativePrice
	coinGeckoTokenFetcher   = fetchCoinGeckoTokenPrice
	backendPriceFetcher     = fetchBackendPrice
)

// GetToken returns price for a specific token contract.
func GetToken(chain, contract, symbol string) (float64, bool) {
	return defaultOracle.GetToken(chain, contract, symbol)
}

// Get returns the USD price for a given chain's native token.
// Returns (price, true) if cached/live; (0, false) if unavailable.
func Get(chain string) (float64, bool) {
	return defaultOracle.Get(chain)
}

func Snapshot() map[string]float64 {
	return defaultOracle.Snapshot()
}

// RestoreForTest replaces the in-memory price cache using Snapshot() keys.
// It is intended for deterministic package-level tests.
func RestoreForTest(snapshot map[string]float64) {
	now := time.Now()
	defaultOracle.mu.Lock()
	defer defaultOracle.mu.Unlock()

	defaultOracle.cache = make(map[string]PriceEntry)
	defaultOracle.tokenCache = make(map[string]PriceEntry)
	for key, price := range snapshot {
		switch {
		case strings.HasPrefix(key, "native:"):
			chain := strings.TrimPrefix(key, "native:")
			if geckoID, ok := chainGeckoID[chain]; ok {
				defaultOracle.cache[geckoID] = PriceEntry{USD: price, FetchedAt: now}
			}
		case strings.HasPrefix(key, "token:"):
			tokenKey := strings.TrimPrefix(key, "token:")
			defaultOracle.tokenCache[tokenKey] = PriceEntry{USD: price, FetchedAt: now}
		}
	}
	defaultOracle.healthy = len(snapshot) > 0
	defaultOracle.lastTryAt = now
	defaultOracle.lastOKAt = now
	defaultOracle.lastError = ""
}

// SetForcedUnavailableForTest forces Get/GetToken to behave as unavailable until cleared.
func SetForcedUnavailableForTest(enabled bool) {
	defaultOracle.mu.Lock()
	defer defaultOracle.mu.Unlock()
	defaultOracle.forcedDown = enabled
	if enabled {
		defaultOracle.healthy = false
		defaultOracle.lastError = "oracle refresh forced unavailable for test"
	} else if defaultOracle.lastError == "oracle refresh forced unavailable for test" {
		defaultOracle.lastError = ""
	}
}

func ForcedUnavailableForTest() bool {
	defaultOracle.mu.RLock()
	defer defaultOracle.mu.RUnlock()
	return defaultOracle.forcedDown
}

// IsHealthy returns true if the oracle has usable native cache.
func IsHealthy() bool {
	return defaultOracle.Status().Healthy
}

// Cache returns a snapshot of all cached prices (for API exposure).
func Cache() map[string]float64 {
	return defaultOracle.Snapshot()
}

func Status() StatusSnapshot {
	return defaultOracle.Status()
}

func EnsureFresh() error {
	return defaultOracle.EnsureFresh()
}

func MaybeRefreshAsync(reason string) {
	defaultOracle.MaybeRefreshAsync(reason)
}

// StartAutoRefresh begins a background goroutine that refreshes prices every TTL.
func StartAutoRefresh() {
	autoRefreshOnce.Do(func() {
		go func() {
			ticker := time.NewTicker(cacheTTL)
			defer ticker.Stop()
			for range ticker.C {
				defaultOracle.refresh()
			}
		}()
	})
}

func (o *Oracle) Get(chain string) (float64, bool) {
	chain = strings.ToLower(strings.TrimSpace(chain))
	geckoID, ok := chainGeckoID[chain]
	if !ok {
		return 0, false
	}

	o.mu.RLock()
	if o.forcedDown {
		o.mu.RUnlock()
		return 0, false
	}
	entry, found := o.cache[geckoID]
	o.mu.RUnlock()

	if found && time.Since(entry.FetchedAt) < cacheTTL {
		return entry.USD, true
	}

	// On-demand fetch only the requested native asset. Do not block on a full refresh.
	if price, err := o.fetchAndStoreNativePrice(chain, geckoID); err == nil && price > 0 {
		return price, true
	}

	o.mu.RLock()
	entry, found = o.cache[geckoID]
	o.mu.RUnlock()
	if found && time.Since(entry.FetchedAt) < maxStaleTTL {
		log.Printf("[oracle] Warning: Using stale native price for %s (fetched %v ago)", chain, time.Since(entry.FetchedAt))
		return entry.USD, true
	}

	return 0, false
}

func (o *Oracle) Status() StatusSnapshot {
	o.mu.RLock()
	defer o.mu.RUnlock()

	staleFor := time.Duration(0)
	if latest := o.latestNativeFetchedAtLocked(); !latest.IsZero() {
		staleFor = time.Since(latest)
	}

	return StatusSnapshot{
		Healthy:            !o.forcedDown && o.hasUsableNativeCacheLocked(),
		ForcedUnavailable:  o.forcedDown,
		LastRefreshAttempt: o.lastTryAt,
		LastRefreshSuccess: o.lastOKAt,
		LastRefreshError:   o.lastError,
		NativeStaleFor:     staleFor,
	}
}

func (o *Oracle) EnsureFresh() error {
	status := o.Status()
	if status.Healthy && status.NativeStaleFor < cacheTTL {
		return nil
	}
	return o.refresh()
}

func (o *Oracle) MaybeRefreshAsync(reason string) {
	o.mu.Lock()
	if o.forcedDown || o.refreshing || o.hasFreshNativeCacheLocked() {
		o.mu.Unlock()
		return
	}
	o.refreshing = true
	o.mu.Unlock()

	go func() {
		defer func() {
			o.mu.Lock()
			o.refreshing = false
			o.mu.Unlock()
		}()
		if err := o.refresh(); err != nil {
			log.Printf("[oracle] background refresh failed (%s): %v", reason, err)
		}
	}()
}

func (o *Oracle) GetToken(chain, contract, symbol string) (float64, bool) {
	if chain == "tempo" {
		return 1, true
	}
	if strings.TrimSpace(contract) == "" || strings.EqualFold(contract, "native") {
		return o.Get(chain)
	}

	o.mu.RLock()
	if o.forcedDown {
		o.mu.RUnlock()
		return 0, false
	}
	o.mu.RUnlock()

	normalizedContract := normalizeTokenKey(chain, contract)
	key := strings.ToLower(strings.TrimSpace(chain)) + ":" + normalizedContract

	o.mu.RLock()
	entry, found := o.tokenCache[key]
	o.mu.RUnlock()

	if found && time.Since(entry.FetchedAt) < cacheTTL {
		return entry.USD, true
	}

	if price, err := o.fetchAndStoreTokenPrice(chain, normalizedContract, symbol); err == nil && price > 0 {
		return price, true
	}

	if found && time.Since(entry.FetchedAt) < maxStaleTTL {
		log.Printf("[oracle] Warning: Using stale token price for %s/%s (fetched %v ago)", chain, normalizedContract, time.Since(entry.FetchedAt))
		return entry.USD, true
	}

	return 0, false
}

func normalizeTokenKey(chain, contract string) string {
	contract = strings.TrimSpace(contract)
	if strings.EqualFold(chain, "solana") {
		return contract
	}
	return strings.ToLower(contract)
}

func (o *Oracle) fetchAndStoreNativePrice(chain, geckoID string) (float64, error) {
	now := time.Now()

	o.mu.Lock()
	if o.forcedDown {
		o.healthy = false
		o.lastTryAt = now
		o.lastError = "oracle refresh forced unavailable for test"
		o.mu.Unlock()
		return 0, fmt.Errorf("oracle refresh forced unavailable for test")
	}
	o.lastTryAt = now
	o.mu.Unlock()

	price, err := fetchNativePrice(chain)

	o.mu.Lock()
	defer o.mu.Unlock()
	if err != nil || price <= 0 {
		if err != nil {
			o.lastError = err.Error()
		}
		o.healthy = !o.forcedDown && o.hasUsableNativeCacheLocked()
		return 0, err
	}

	o.cache[geckoID] = PriceEntry{USD: price, FetchedAt: now}
	o.lastOKAt = now
	o.lastError = ""
	o.healthy = !o.forcedDown && o.hasUsableNativeCacheLocked()
	return price, nil
}

func (o *Oracle) fetchAndStoreTokenPrice(chain, contract, symbol string) (float64, error) {
	now := time.Now()

	o.mu.Lock()
	if o.forcedDown {
		o.lastTryAt = now
		o.lastError = "oracle refresh forced unavailable for test"
		o.mu.Unlock()
		return 0, fmt.Errorf("oracle refresh forced unavailable for test")
	}
	o.lastTryAt = now
	o.mu.Unlock()

	price, err := fetchTokenPrice(chain, contract, symbol)

	o.mu.Lock()
	defer o.mu.Unlock()
	if err != nil || price <= 0 {
		if err != nil {
			o.lastError = err.Error()
		}
		return 0, err
	}

	key := strings.ToLower(strings.TrimSpace(chain)) + ":" + normalizeTokenKey(chain, contract)
	o.tokenCache[key] = PriceEntry{USD: price, FetchedAt: now}
	o.lastOKAt = now
	o.lastError = ""
	return price, nil
}

func fetchNativePrice(chain string) (float64, error) {
	if p, err := coinGeckoNativeFetcher(chain); err == nil && p > 0 {
		return p, nil
	}

	p, err := backendPriceFetcher(chain, "", "")
	if err == nil && p > 0 {
		return p, nil
	}
	if err != nil {
		return 0, err
	}
	return 0, fmt.Errorf("native price unavailable for %s", chain)
}

func fetchTokenPrice(chain, contract, symbol string) (float64, error) {
	if p, err := dexScreenerPriceFetcher(chain, contract); err == nil && p > 0 {
		return p, nil
	}

	if p, err := coinGeckoTokenFetcher(chain, contract); err == nil && p > 0 {
		return p, nil
	}

	p, err := backendPriceFetcher(chain, contract, symbol)
	if err == nil && p > 0 {
		return p, nil
	}
	if err != nil {
		return 0, err
	}
	return 0, fmt.Errorf("token price unavailable for %s/%s", chain, contract)
}

func fetchDexScreener(chain, contract string) (float64, error) {
	urlStr := fmt.Sprintf("https://api.dexscreener.com/latest/dex/tokens/%s", contract)
	client := &http.Client{Timeout: apiTimeout}
	resp, err := client.Get(urlStr)
	if err != nil {
		return 0, err
	}
	defer resp.Body.Close()

	var data struct {
		Pairs []struct {
			ChainId   string `json:"chainId"`
			PriceUsd  string `json:"priceUsd"`
			BaseToken struct {
				Symbol string `json:"symbol"`
			} `json:"baseToken"`
			Liquidity struct {
				USD float64 `json:"usd"`
			} `json:"liquidity"`
		} `json:"pairs"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&data); err != nil {
		return 0, err
	}
	if len(data.Pairs) == 0 {
		return 0, fmt.Errorf("dexscreener: no pairs for %s", contract)
	}

	chain = strings.ToLower(strings.TrimSpace(chain))
	bestPrice := 0.0
	bestLiq := 0.0
	found := false

	for _, pair := range data.Pairs {
		if pair.Liquidity.USD < 1000 {
			continue
		}
		if !strings.EqualFold(pair.ChainId, chain) {
			continue
		}
		price, err := strconv.ParseFloat(strings.TrimSpace(pair.PriceUsd), 64)
		if err != nil || price <= 0 {
			continue
		}
		if pair.Liquidity.USD > bestLiq {
			bestLiq = pair.Liquidity.USD
			bestPrice = price
			found = true
		}
	}
	if found {
		return bestPrice, nil
	}

	for _, pair := range data.Pairs {
		if pair.Liquidity.USD < 500 {
			continue
		}
		price, err := strconv.ParseFloat(strings.TrimSpace(pair.PriceUsd), 64)
		if err != nil || price <= 0 {
			continue
		}
		if pair.Liquidity.USD > bestLiq {
			bestLiq = pair.Liquidity.USD
			bestPrice = price
			found = true
		}
	}
	if found {
		return bestPrice, nil
	}
	return 0, fmt.Errorf("dexscreener: insufficient liquidity for %s", contract)
}

func fetchCoinGeckoNativePrice(chain string) (float64, error) {
	chain = strings.ToLower(strings.TrimSpace(chain))
	id, ok := chainGeckoID[chain]
	if !ok || id == "" {
		return 0, fmt.Errorf("coingecko native: unsupported chain %s", chain)
	}

	var raw map[string]map[string]float64
	if err := httpGetJSONWithTimeout(geckoBase+url.QueryEscape(id), &raw); err != nil {
		return 0, fmt.Errorf("coingecko native %s: %w", chain, err)
	}
	entry := raw[id]
	if entry == nil || entry["usd"] <= 0 {
		return 0, fmt.Errorf("coingecko native %s: missing usd price", chain)
	}
	return entry["usd"], nil
}

func fetchCoinGeckoTokenPrice(chain, contract string) (float64, error) {
	chain = strings.ToLower(strings.TrimSpace(chain))
	contract = strings.TrimSpace(contract)
	if contract == "" {
		return 0, fmt.Errorf("coingecko token: empty contract")
	}
	if strings.HasPrefix(strings.ToLower(contract), "0x") {
		contract = strings.ToLower(contract)
	}

	platform, ok := chainCoinGeckoPlatform[chain]
	if !ok || platform == "" {
		return 0, fmt.Errorf("coingecko token: unsupported chain %s", chain)
	}

	q := url.Values{}
	q.Set("vs_currencies", "usd")
	q.Set("contract_addresses", contract)
	u := "https://api.coingecko.com/api/v3/simple/token_price/" + platform + "?" + q.Encode()

	var raw map[string]map[string]float64
	if err := httpGetJSONWithTimeout(u, &raw); err != nil {
		return 0, fmt.Errorf("coingecko token %s/%s: %w", chain, contract, err)
	}
	for _, entry := range raw {
		if entry["usd"] > 0 {
			return entry["usd"], nil
		}
	}
	return 0, fmt.Errorf("coingecko token %s/%s: missing usd price", chain, contract)
}

func fetchBackendPrice(chain, contract, symbol string) (float64, error) {
	baseURL := strings.TrimRight(resolveBackendBaseURL(), "/")
	if baseURL == "" {
		return 0, fmt.Errorf("backend fallback unavailable: missing backend url")
	}

	payload := []map[string]string{{
		"chain":         strings.ToLower(strings.TrimSpace(chain)),
		"token_address": strings.TrimSpace(contract),
		"symbol":        strings.TrimSpace(symbol),
	}}
	body, err := json.Marshal(payload)
	if err != nil {
		return 0, err
	}

	ctx, cancel := context.WithTimeout(context.Background(), apiTimeout)
	defer cancel()

	req, err := http.NewRequestWithContext(ctx, http.MethodPost, baseURL+"/api/v1/prices", bytes.NewReader(body))
	if err != nil {
		return 0, err
	}
	req.Header.Set("Content-Type", "application/json")

	resp, err := (&http.Client{}).Do(req)
	if err != nil {
		return 0, fmt.Errorf("backend fallback request failed: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		raw, _ := io.ReadAll(io.LimitReader(resp.Body, 2048))
		return 0, fmt.Errorf("backend fallback returned %d: %s", resp.StatusCode, strings.TrimSpace(string(raw)))
	}

	var out struct {
		Data []struct {
			PriceUSD float64 `json:"price_usd"`
		} `json:"data"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&out); err != nil {
		return 0, fmt.Errorf("backend fallback decode failed: %w", err)
	}
	if len(out.Data) == 0 || out.Data[0].PriceUSD <= 0 {
		return 0, fmt.Errorf("backend fallback returned no price for %s/%s", chain, contract)
	}
	return out.Data[0].PriceUSD, nil
}

func resolveBackendBaseURL() string {
	if v := strings.TrimSpace(os.Getenv("CLAY_BACKEND_URL")); v != "" {
		return v
	}
	if v := strings.TrimSpace(os.Getenv("RELAY_URL")); v != "" {
		return v
	}
	return "http://127.0.0.1:8080"
}

func httpGetJSONWithTimeout(urlStr string, out any) error {
	ctx, cancel := context.WithTimeout(context.Background(), apiTimeout)
	defer cancel()

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, urlStr, nil)
	if err != nil {
		return err
	}

	resp, err := (&http.Client{}).Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		raw, _ := io.ReadAll(io.LimitReader(resp.Body, 2048))
		return fmt.Errorf("http %d: %s", resp.StatusCode, strings.TrimSpace(string(raw)))
	}

	return json.NewDecoder(resp.Body).Decode(out)
}

func (o *Oracle) Snapshot() map[string]float64 {
	o.mu.RLock()
	defer o.mu.RUnlock()

	out := make(map[string]float64)
	for chain, gid := range chainGeckoID {
		if entry, ok := o.cache[gid]; ok {
			out["native:"+chain] = entry.USD
		}
	}
	for key, entry := range o.tokenCache {
		out["token:"+key] = entry.USD
	}
	return out
}

func (o *Oracle) hasFreshNativeCacheLocked() bool {
	return o.hasNativeCacheWithinLocked(cacheTTL)
}

func (o *Oracle) hasUsableNativeCacheLocked() bool {
	return o.hasNativeCacheWithinLocked(maxStaleTTL)
}

func (o *Oracle) hasNativeCacheWithinLocked(ttl time.Duration) bool {
	now := time.Now()
	for _, entry := range o.cache {
		if entry.USD > 0 && now.Sub(entry.FetchedAt) < ttl {
			return true
		}
	}
	return false
}

func (o *Oracle) latestNativeFetchedAtLocked() time.Time {
	var latest time.Time
	for _, entry := range o.cache {
		if entry.USD <= 0 {
			continue
		}
		if entry.FetchedAt.After(latest) {
			latest = entry.FetchedAt
		}
	}
	return latest
}

func nativeChainsByGeckoID() map[string][]string {
	out := make(map[string][]string, len(chainGeckoID))
	for chain, gid := range chainGeckoID {
		if strings.TrimSpace(gid) == "" {
			continue
		}
		out[gid] = append(out[gid], chain)
	}
	return out
}

func (o *Oracle) refreshNativePricesFromBatch(raw map[string]map[string]float64) (int, error) {
	now := time.Now()
	updatedIDs := make(map[string]struct{}, len(raw))
	updated := 0

	o.mu.Lock()
	for id, prices := range raw {
		if prices["usd"] <= 0 {
			continue
		}
		o.cache[id] = PriceEntry{USD: prices["usd"], FetchedAt: now}
		updatedIDs[id] = struct{}{}
		updated++
	}
	o.mu.Unlock()

	var refreshErr error
	for gid, chains := range nativeChainsByGeckoID() {
		if _, ok := updatedIDs[gid]; ok {
			continue
		}

		var lastErr error
		for _, chain := range chains {
			price, err := fetchNativePrice(chain)
			if err != nil || price <= 0 {
				if err != nil {
					lastErr = err
				}
				continue
			}
			o.mu.Lock()
			o.cache[gid] = PriceEntry{USD: price, FetchedAt: now}
			o.mu.Unlock()
			updated++
			lastErr = nil
			break
		}
		if lastErr != nil && refreshErr == nil {
			refreshErr = lastErr
		}
	}

	return updated, refreshErr
}

func (o *Oracle) refresh() error {
	now := time.Now()
	o.mu.Lock()
	if o.forcedDown {
		o.healthy = false
		o.lastTryAt = now
		o.lastError = "oracle refresh forced unavailable for test"
		o.mu.Unlock()
		return fmt.Errorf("oracle refresh forced unavailable for test")
	}
	o.lastTryAt = now
	o.mu.Unlock()

	seen := map[string]bool{}
	ids := make([]string, 0, len(chainGeckoID))
	for _, gid := range chainGeckoID {
		if seen[gid] {
			continue
		}
		seen[gid] = true
		ids = append(ids, gid)
	}

	updated := 0
	var refreshErr error
	var raw map[string]map[string]float64

	if len(ids) > 0 {
		if err := httpGetJSONWithTimeout(geckoBase+strings.Join(ids, ","), &raw); err != nil {
			log.Printf("[oracle] batch CoinGecko fetch failed: %v", err)
			refreshErr = fmt.Errorf("price fetch failed: %w", err)
		}
	}

	fallbackUpdated, fallbackErr := o.refreshNativePricesFromBatch(raw)
	updated += fallbackUpdated
	if refreshErr == nil && fallbackErr != nil {
		refreshErr = fallbackErr
	}

	o.mu.Lock()
	o.healthy = !o.forcedDown && (updated > 0 || o.hasUsableNativeCacheLocked())
	if updated > 0 {
		o.lastOKAt = now
		o.lastError = ""
	} else if refreshErr != nil {
		o.lastError = refreshErr.Error()
	}
	o.mu.Unlock()

	log.Printf("[oracle] Price cache refreshed: %d coins (healthy=%t)", updated, o.Status().Healthy)
	if updated == 0 && refreshErr != nil {
		return refreshErr
	}
	return nil
}
