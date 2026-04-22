package assets

import (
	"bytes"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"math/big"
	"net/http"
	"os"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"

	"sandbox/internals/oracle"
	"sandbox/internals/security"
	"sandbox/internals/utils"
)

// Asset holds a single token's balance and metadata
type Asset struct {
	Chain           string  `json:"chain"`
	ContractAddress string  `json:"contract_address"`
	Symbol          string  `json:"symbol"`
	BalanceStr      string  `json:"balance_str"`
	Decimals        int     `json:"decimals"`
	UIBalance       float64 `json:"ui_balance"`
	ExplorerURL     string  `json:"explorer_url,omitempty"`
}

// Transaction holds a generic activity record across chains
type Transaction struct {
	Chain           string    `json:"chain"`
	Hash            string    `json:"hash"`
	From            string    `json:"from"`
	To              string    `json:"to"`
	Amount          string    `json:"amount"` // Human readable
	Symbol          string    `json:"symbol"`
	ContractAddress string    `json:"contract_address,omitempty"`
	Direction       string    `json:"direction,omitempty"` // "outgoing" or "incoming"
	Timestamp       time.Time `json:"timestamp"`
	Status          string    `json:"status"` // "success", "failed", "pending"
	ExplorerURL     string    `json:"explorer_url,omitempty"`
}

type DailyUsage struct {
	SpentUSD  float64   `json:"spent_usd"`
	TxCount   int       `json:"tx_count"`
	UpdatedAt time.Time `json:"updated_at"`
}

type cacheData struct {
	Assets            []Asset       `json:"assets"`
	History           []Transaction `json:"history"`
	UpdatedAt         time.Time     `json:"updated_at"`
	HistoryUpdatedAt  time.Time     `json:"history_updated_at,omitempty"`
	InitializedAt     time.Time     `json:"initialized_at,omitempty"`
	LastRefreshStart  time.Time     `json:"last_refresh_start_at,omitempty"`
	LastRefreshTryAt  time.Time     `json:"last_refresh_try_at,omitempty"`
	LastFastRefreshAt time.Time     `json:"last_fast_refresh_at,omitempty"`
	WalletAddress     string        `json:"wallet_address,omitempty"`
	WalletExplorerURL string        `json:"wallet_explorer_url,omitempty"`
}

type tokenMetaCacheEntry struct {
	Symbol   string `json:"symbol,omitempty"`
	Decimals int    `json:"decimals,omitempty"`
}

type slowChainState struct {
	ContractScanBlock int
	HistoryScanBlock  int
	KnownContracts    []string
	LastNativeTxCount int
	LastTouchedAt     time.Time
}

type RefreshState struct {
	Chain      string    `json:"chain"`
	Address    string    `json:"address"`
	InFlight   bool      `json:"in_flight"`
	StartedAt  time.Time `json:"started_at,omitempty"`
	InflightMS int64     `json:"inflight_ms,omitempty"`
}

type CacheStateView struct {
	Chain             string    `json:"chain"`
	Address           string    `json:"address"`
	InitializedAt     time.Time `json:"initialized_at,omitempty"`
	UpdatedAt         time.Time `json:"updated_at,omitempty"`
	HistoryUpdatedAt  time.Time `json:"history_updated_at,omitempty"`
	LastRefreshStart  time.Time `json:"last_refresh_start_at,omitempty"`
	LastRefreshTryAt  time.Time `json:"last_refresh_try_at,omitempty"`
	LastFastRefreshAt time.Time `json:"last_fast_refresh_at,omitempty"`
	AssetCount        int       `json:"asset_count"`
	HistoryCount      int       `json:"history_count"`
}

type tempoTrackedToken struct {
	Address string
	Symbol  string
}

const (
	tempoPathUSD = "0x20c0000000000000000000000000000000000000"
	tempoUSDCe   = "0x20c000000000000000000000b9537d11c60e8b50"
	tempoEURCe   = "0x20c0000000000000000000001621e21f71cf12fb"
	tempoUSDT0   = "0x20c00000000000000000000014f22ca97301eb73"
)

var (
	mu                 sync.RWMutex
	globalCache        = make(map[string]cacheData) // keyed by "chain:address"
	symCache           = make(map[string]string)    // "chain:contract" -> symbol
	decCache           = make(map[string]int)       // "chain:contract" -> decimals
	tempoTrackedTokens = []tempoTrackedToken{
		{Address: tempoPathUSD, Symbol: "pathUSD"},
		{Address: tempoUSDCe, Symbol: "USDCe"},
		{Address: tempoEURCe, Symbol: "EURCe"},
		{Address: tempoUSDT0, Symbol: "USDT0"},
	}

	slowChainMu          sync.Mutex
	slowChainStates      = make(map[string]slowChainState)
	slowChainRefreshing  = make(map[string]time.Time)
	slowChainRefreshDone = make(map[string]chan struct{})
	slowChainStateOnce   sync.Once
	slowChainStateSaveMu sync.Mutex
	cacheStateOnce       sync.Once
	cacheStateSaveMu     sync.Mutex
	autoRefreshOnce      sync.Once
	startupFastRefreshMu sync.Mutex
	startupFastRefresh   = make(map[string]struct{})

	client              = &http.Client{Timeout: 10 * time.Second}
	refreshChainCacheFn = refreshChainCache
	fetchFreeChainData  = FetchFreeChainData
	zeroGAnkrRPC        = "https://rpc.ankr.com/0g_mainnet_evm"
	zeroGOfficialRPC    = "https://evmrpc.0g.ai"
	zeroGPublicNodeRPC  = "https://0g-rpc.publicnode.com"
	zeroGOriginStakeRPC = "https://infra.originstake.com/0g/evm"
	ethereumPublicRPCs  = []string{
		"https://eth.drpc.org",
		"https://1rpc.io/eth",
		"https://ethereum-rpc.publicnode.com",
	}
	tempoPublicRPCs = []string{
		"https://rpc.moderato.tempo.xyz",
	}
	basePublicRPCs = []string{
		"https://rpc.sentio.xyz/base",
		"https://developer-access-mainnet.base.org",
		"https://base.rpc.subquery.network/public",
		"https://base-mainnet.public.blastapi.io",
		"https://api.zan.top/base-mainnet",
		"https://base.llamarpc.com",
		"https://mainnet.base.org",
		"https://base-rpc.publicnode.com",
	}
	optimismPublicRPCs = []string{
		"https://mainnet.optimism.io",
	}
	arbitrumPublicRPCs = []string{
		"https://arbitrum.gateway.tenderly.co",
		"https://arbitrum.drpc.org",
		"https://arb1.arbitrum.io/rpc",
		"https://arbitrum-one.public.blastapi.io",
		"https://arbitrum-one-rpc.publicnode.com",
	}
	polygonPublicRPCs = []string{
		"https://polygon-bor-rpc.publicnode.com",
	}
	bscPublicRPCs = []string{
		"https://public-bsc-mainnet.fastnode.io",
		"https://api-bsc-mainnet-full.n.dwellir.com/2ccf18bf-2916-4198-8856-42172854353c",
		"https://rpc.owlracle.info/bsc/70d38ce1826c4a60bb2a8e05a6c8b20f",
		"https://bsc.api.pocket.network",
		"https://binance.llamarpc.com",
		"https://bsc-dataseed1.defibit.io",
		"https://public-bsc.nownodes.io",
		"https://bsc.drpc.org",
		"https://bnb.rpc.subquery.network/public",
		"https://bsc-dataseed.bnbchain.org",
		"https://bsc-dataseed-public.bnbchain.org",
	}
	monadPublicRPCs = []string{
		"https://rpc2.monad.xyz",
		"https://rpc1.monad.xyz",
		"https://rpc3.monad.xyz",
		"https://rpc.monad.xyz",
		"https://rpc-mainnet.monadinfra.com",
	}
	kitePublicRPCs = []string{
		"https://rpc.gokite.ai/",
	}
)

const (
	defaultRefreshTTL        = 60 * time.Second
	defaultHistoryRefreshTTL = 30 * time.Second
	fullChainRefreshTimeout  = 30 * time.Second
	historyChainRefreshTTL   = 3 * time.Second
	slowChainLookbackBlocks  = 50_000
	wideLogLookbackBlocks    = 10_000
	narrowLogLookbackBlocks  = 1_000
	slowChainOverlapBlocks   = 256
	slowChainStateLimit      = 1_000_000
	slowChainStateFileName   = "asset_cursors.json"
	assetCacheFileName       = "asset_cache.json"
	autoRefreshInterval      = 5 * time.Minute
	manualRefreshThrottle    = 15 * time.Second
	preActionRefreshTTL      = 60 * time.Second
	staleFastRefreshAfter    = 60 * time.Minute
	persistedHistoryTTL      = 30 * 24 * time.Hour
	persistedHistoryLimit    = 1000
	fullRefreshHistoryLimit  = persistedHistoryLimit
	usageFactsHistoryLimit   = 50
)

var evmRefreshChains = []string{"ethereum", "0g", "arbitrum", "bsc", "base", "monad", "tempo", "kite"}

const disableAlchemyEnv = "CLAY_DISABLE_ALCHEMY"
const alchemyRPCEnvPrefix = "CLAY_ALCHEMY_RPC_"
const disableExplorerFallbackEnv = "CLAY_DISABLE_EXPLORER_FALLBACK"

func IsNonBlockingRefreshChain(chain string) bool {
	switch strings.ToLower(strings.TrimSpace(chain)) {
	case "0g", "monad", "kite":
		return true
	default:
		return false
	}
}

func usesPersistentCursorChain(chain string) bool {
	switch strings.ToLower(strings.TrimSpace(chain)) {
	case "ethereum", "0g", "base", "bsc", "arbitrum", "optimism", "polygon", "monad", "tempo", "kite":
		return true
	default:
		return false
	}
}

func slowChainStateKey(chain, address string) string {
	return strings.ToLower(strings.TrimSpace(chain)) + ":" + strings.TrimSpace(address)
}

func slowChainStatePath() string {
	if path := strings.TrimSpace(os.Getenv("CLAY_ASSET_CURSOR_PATH")); path != "" {
		return path
	}
	return slowChainStateFileName
}

func assetCachePath() string {
	if path := strings.TrimSpace(os.Getenv("CLAY_ASSET_CACHE_PATH")); path != "" {
		return path
	}
	return assetCacheFileName
}

func ensureCacheLoaded() {
	cacheStateOnce.Do(func() {
		path := assetCachePath()
		data, err := os.ReadFile(path)
		if err != nil {
			if !os.IsNotExist(err) {
				log.Printf("[claw wallet assets] Failed to load asset cache from %s: %v", path, err)
			}
			return
		}

		var payload struct {
			Version   int                            `json:"version"`
			Entries   map[string]cacheData           `json:"entries"`
			TokenMeta map[string]tokenMetaCacheEntry `json:"token_meta,omitempty"`
		}
		if err := json.Unmarshal(data, &payload); err != nil {
			log.Printf("[claw wallet assets] Failed to parse asset cache from %s: %v", path, err)
			return
		}

		mu.Lock()
		globalCache = sanitizeCacheEntries(payload.Entries)
		mergeTokenMetaLocked(payload.TokenMeta)
		mergeTokenMetaFromCacheEntriesLocked(globalCache)
		mu.Unlock()
	})
}

func mergeTokenMetaLocked(entries map[string]tokenMetaCacheEntry) {
	for key, entry := range entries {
		cacheKey := strings.ToLower(strings.TrimSpace(key))
		if cacheKey == "" {
			continue
		}
		if symbol := strings.TrimSpace(entry.Symbol); symbol != "" {
			symCache[cacheKey] = symbol
		}
		if entry.Decimals > 0 {
			decCache[cacheKey] = entry.Decimals
		}
	}
}

func mergeTokenMetaFromCacheEntriesLocked(entries map[string]cacheData) {
	for chainAddress, entry := range entries {
		parts := strings.SplitN(chainAddress, ":", 2)
		if len(parts) != 2 {
			continue
		}
		chain := strings.ToLower(strings.TrimSpace(parts[0]))
		for _, asset := range entry.Assets {
			contract := strings.TrimSpace(asset.ContractAddress)
			if contract == "" {
				continue
			}
			key := strings.ToLower(chain + ":" + contract)
			if symbol := strings.TrimSpace(asset.Symbol); symbol != "" {
				symCache[key] = symbol
			}
			if asset.Decimals > 0 {
				decCache[key] = asset.Decimals
			}
		}
	}
}

func sanitizeCacheEntries(entries map[string]cacheData) map[string]cacheData {
	if len(entries) == 0 {
		return make(map[string]cacheData)
	}
	out := make(map[string]cacheData, len(entries))
	for key, entry := range entries {
		out[key] = sanitizeCacheEntry(entry)
	}
	return out
}

func sanitizeCacheEntry(entry cacheData) cacheData {
	cutoff := time.Now().UTC().Add(-persistedHistoryTTL)
	if len(entry.History) > 0 {
		filtered := make([]Transaction, 0, len(entry.History))
		for _, tx := range entry.History {
			if tx.Timestamp.IsZero() || tx.Timestamp.UTC().After(cutoff) {
				filtered = append(filtered, tx)
			}
		}
		sort.SliceStable(filtered, func(i, j int) bool {
			if filtered[i].Timestamp.Equal(filtered[j].Timestamp) {
				return filtered[i].Hash > filtered[j].Hash
			}
			return filtered[i].Timestamp.After(filtered[j].Timestamp)
		})
		if len(filtered) > persistedHistoryLimit {
			filtered = filtered[:persistedHistoryLimit]
		}
		entry.History = filtered
	}
	return entry
}

func cloneGlobalCacheLocked() map[string]cacheData {
	if len(globalCache) == 0 {
		return nil
	}
	out := make(map[string]cacheData, len(globalCache))
	for key, entry := range globalCache {
		out[key] = sanitizeCacheEntry(entry)
	}
	return out
}

func cloneTokenMetaLocked() map[string]tokenMetaCacheEntry {
	if len(symCache) == 0 && len(decCache) == 0 {
		return nil
	}
	keys := make(map[string]struct{}, len(symCache)+len(decCache))
	for key := range symCache {
		keys[key] = struct{}{}
	}
	for key := range decCache {
		keys[key] = struct{}{}
	}
	out := make(map[string]tokenMetaCacheEntry, len(keys))
	for key := range keys {
		entry := tokenMetaCacheEntry{
			Symbol:   strings.TrimSpace(symCache[key]),
			Decimals: decCache[key],
		}
		if entry.Symbol == "" && entry.Decimals <= 0 {
			continue
		}
		out[key] = entry
	}
	return out
}

func persistGlobalCache() {
	ensureCacheLoaded()
	mu.RLock()
	snapshot := cloneGlobalCacheLocked()
	tokenMeta := cloneTokenMetaLocked()
	mu.RUnlock()

	payload := struct {
		Version   int                            `json:"version"`
		Entries   map[string]cacheData           `json:"entries"`
		TokenMeta map[string]tokenMetaCacheEntry `json:"token_meta,omitempty"`
	}{
		Version:   1,
		Entries:   snapshot,
		TokenMeta: tokenMeta,
	}
	data, err := json.Marshal(payload)
	if err != nil {
		log.Printf("[claw wallet assets] Failed to encode asset cache: %v", err)
		return
	}

	path := assetCachePath()
	if dir := strings.TrimSpace(filepath.Dir(path)); dir != "" && dir != "." {
		if err := os.MkdirAll(dir, 0755); err != nil {
			log.Printf("[claw wallet assets] Failed to create asset cache dir %s: %v", dir, err)
			return
		}
	}

	cacheStateSaveMu.Lock()
	defer cacheStateSaveMu.Unlock()
	if err := utils.AtomicWrite(path, data); err != nil {
		log.Printf("[claw wallet assets] Failed to persist asset cache to %s: %v", path, err)
	}
}

func ensureSlowChainStatesLoaded() {
	slowChainStateOnce.Do(func() {
		path := slowChainStatePath()
		data, err := os.ReadFile(path)
		if err != nil {
			if !os.IsNotExist(err) {
				log.Printf("[claw wallet assets] Failed to load asset cursors from %s: %v", path, err)
			}
			return
		}

		var payload struct {
			Version int                       `json:"version"`
			States  map[string]slowChainState `json:"states"`
		}
		if err := json.Unmarshal(data, &payload); err != nil {
			log.Printf("[claw wallet assets] Failed to parse asset cursors from %s: %v", path, err)
			return
		}

		slowChainMu.Lock()
		if len(payload.States) > 0 {
			slowChainStates = payload.States
			pruneSlowChainStatesLocked(slowChainStateLimit)
		}
		slowChainMu.Unlock()
	})
}

func tryStartSlowChainRefresh(chain, address string) bool {
	ensureSlowChainStatesLoaded()
	key := slowChainStateKey(chain, address)
	if key == ":" {
		return true
	}

	slowChainMu.Lock()
	defer slowChainMu.Unlock()

	if startedAt, ok := slowChainRefreshing[key]; ok {
		log.Printf("[claw wallet assets] Slow-chain refresh already running for %s (inflight=%s)", key, time.Since(startedAt).Round(time.Millisecond))
		return false
	}
	slowChainRefreshing[key] = time.Now()
	slowChainRefreshDone[key] = make(chan struct{})
	return true
}

func finishSlowChainRefresh(chain, address string) {
	ensureSlowChainStatesLoaded()
	key := slowChainStateKey(chain, address)
	if key == ":" {
		return
	}

	slowChainMu.Lock()
	done := slowChainRefreshDone[key]
	delete(slowChainRefreshDone, key)
	delete(slowChainRefreshing, key)
	slowChainMu.Unlock()
	if done != nil {
		close(done)
	}
}

func getSlowChainState(chain, address string) slowChainState {
	ensureSlowChainStatesLoaded()
	key := slowChainStateKey(chain, address)
	slowChainMu.Lock()
	defer slowChainMu.Unlock()
	state, ok := slowChainStates[key]
	if ok {
		state.LastTouchedAt = time.Now()
		slowChainStates[key] = state
	}
	return state
}

func updateSlowChainState(chain, address string, apply func(*slowChainState)) {
	ensureSlowChainStatesLoaded()
	key := slowChainStateKey(chain, address)
	slowChainMu.Lock()
	state := slowChainStates[key]
	apply(&state)
	state.LastTouchedAt = time.Now().UTC()
	slowChainStates[key] = state
	pruneSlowChainStatesLocked(slowChainStateLimit)
	snapshot := cloneSlowChainStatesLocked()
	slowChainMu.Unlock()

	persistSlowChainStates(snapshot)
}

func pruneSlowChainStatesLocked(limit int) {
	if limit <= 0 || len(slowChainStates) <= limit {
		return
	}

	type evictionCandidate struct {
		key        string
		lastAccess time.Time
	}

	candidates := make([]evictionCandidate, 0, len(slowChainStates))
	for key, state := range slowChainStates {
		if _, inflight := slowChainRefreshing[key]; inflight {
			continue
		}
		candidates = append(candidates, evictionCandidate{
			key:        key,
			lastAccess: state.LastTouchedAt,
		})
	}
	if len(candidates) == 0 {
		return
	}

	sort.Slice(candidates, func(i, j int) bool {
		if candidates[i].lastAccess.Equal(candidates[j].lastAccess) {
			return candidates[i].key < candidates[j].key
		}
		if candidates[i].lastAccess.IsZero() {
			return true
		}
		if candidates[j].lastAccess.IsZero() {
			return false
		}
		return candidates[i].lastAccess.Before(candidates[j].lastAccess)
	})

	toDelete := len(slowChainStates) - limit
	if toDelete > len(candidates) {
		toDelete = len(candidates)
	}
	for i := 0; i < toDelete; i++ {
		delete(slowChainStates, candidates[i].key)
	}
}

func cloneSlowChainStatesLocked() map[string]slowChainState {
	if len(slowChainStates) == 0 {
		return nil
	}
	out := make(map[string]slowChainState, len(slowChainStates))
	for key, state := range slowChainStates {
		out[key] = state
	}
	return out
}

func persistSlowChainStates(states map[string]slowChainState) {
	payload := struct {
		Version int                       `json:"version"`
		States  map[string]slowChainState `json:"states"`
	}{
		Version: 1,
		States:  states,
	}
	data, err := json.Marshal(payload)
	if err != nil {
		log.Printf("[claw wallet assets] Failed to encode asset cursors: %v", err)
		return
	}

	path := slowChainStatePath()
	if dir := strings.TrimSpace(filepath.Dir(path)); dir != "" && dir != "." {
		if err := os.MkdirAll(dir, 0755); err != nil {
			log.Printf("[claw wallet assets] Failed to create asset cursor dir %s: %v", dir, err)
			return
		}
	}

	slowChainStateSaveMu.Lock()
	defer slowChainStateSaveMu.Unlock()
	if err := utils.AtomicWrite(path, data); err != nil {
		log.Printf("[claw wallet assets] Failed to persist asset cursors to %s: %v", path, err)
	}
}

func WaitForSlowChainRefresh(chain, address string) (startedAt time.Time, done <-chan struct{}) {
	ensureSlowChainStatesLoaded()
	key := slowChainStateKey(chain, address)
	slowChainMu.Lock()
	defer slowChainMu.Unlock()

	startedAt = slowChainRefreshing[key]
	done = slowChainRefreshDone[key]
	if done == nil {
		return time.Time{}, nil
	}
	return startedAt, done
}

func RefreshStateSnapshot() map[string]RefreshState {
	ensureSlowChainStatesLoaded()
	now := time.Now()

	slowChainMu.Lock()
	defer slowChainMu.Unlock()

	out := make(map[string]RefreshState, len(slowChainRefreshing))
	for key, startedAt := range slowChainRefreshing {
		parts := strings.SplitN(key, ":", 2)
		state := RefreshState{
			InFlight:   true,
			StartedAt:  startedAt.UTC(),
			InflightMS: now.Sub(startedAt).Milliseconds(),
		}
		if len(parts) > 0 {
			state.Chain = parts[0]
		}
		if len(parts) > 1 {
			state.Address = parts[1]
		}
		out[key] = state
	}
	return out
}

func firstPublicRPCEndpoint(endpoints []string) string {
	for _, endpoint := range endpoints {
		endpoint = strings.TrimSpace(endpoint)
		if endpoint == "" {
			continue
		}
		if strings.Contains(endpoint, "alchemy.com") {
			continue
		}
		return endpoint
	}
	return ""
}

func maxLogRangeForEndpoint(endpoint string) int {
	endpoint = strings.ToLower(strings.TrimSpace(endpoint))
	switch {
	case endpoint == "":
		return wideLogLookbackBlocks
	case strings.Contains(endpoint, "rpc2.monad.xyz"):
		return wideLogLookbackBlocks
	case strings.Contains(endpoint, "eth.drpc.org"),
		strings.Contains(endpoint, "1rpc.io/eth"):
		return wideLogLookbackBlocks
	case strings.Contains(endpoint, "rpc1.monad.xyz"),
		strings.Contains(endpoint, "rpc3.monad.xyz"),
		strings.Contains(endpoint, "ethereum-rpc.publicnode.com"),
		strings.Contains(endpoint, "ethereum.publicnode.com"):
		return narrowLogLookbackBlocks
	case strings.Contains(endpoint, "rpc.monad.xyz"),
		strings.Contains(endpoint, "rpc-mainnet.monadinfra.com"):
		return 100
	default:
		return wideLogLookbackBlocks
	}
}

func logLookbackBlocksForEndpoints(endpoints []string) int {
	if maxLogRangeForEndpoint(firstPublicRPCEndpoint(endpoints)) >= wideLogLookbackBlocks {
		return wideLogLookbackBlocks
	}
	return narrowLogLookbackBlocks
}

func slowChainLogLowerBound(chain, address string, head int, endpoints []string) int {
	lowerBound := maxInt(head-logLookbackBlocksForEndpoints(endpoints), 0)
	if !usesPersistentCursorChain(chain) {
		return lowerBound
	}

	state := getSlowChainState(chain, address)
	if state.HistoryScanBlock > 0 {
		cursorLowerBound := maxInt(state.HistoryScanBlock-slowChainOverlapBlocks, 0)
		if cursorLowerBound > lowerBound {
			lowerBound = cursorLowerBound
		}
	}
	return lowerBound
}

func slowChainContractLowerBound(chain, address string, head int, endpoints []string) int {
	lowerBound := maxInt(head-logLookbackBlocksForEndpoints(endpoints), 0)
	if !usesPersistentCursorChain(chain) {
		return lowerBound
	}

	state := getSlowChainState(chain, address)
	if state.ContractScanBlock > 0 {
		cursorLowerBound := maxInt(state.ContractScanBlock-slowChainOverlapBlocks, 0)
		if cursorLowerBound > lowerBound {
			lowerBound = cursorLowerBound
		}
	}
	return lowerBound
}

func mergeHistory(existing, incoming []Transaction, limit int) []Transaction {
	if limit <= 0 {
		limit = 50
	}
	if len(existing) == 0 {
		if len(incoming) > limit {
			return append([]Transaction(nil), incoming[:limit]...)
		}
		return append([]Transaction(nil), incoming...)
	}
	if len(incoming) == 0 {
		if len(existing) > limit {
			return append([]Transaction(nil), existing[:limit]...)
		}
		return append([]Transaction(nil), existing...)
	}

	merged := make([]Transaction, 0, len(existing)+len(incoming))
	seen := make(map[string]struct{}, len(existing)+len(incoming))
	appendTx := func(tx Transaction) {
		key := strings.Join([]string{
			strings.ToLower(strings.TrimSpace(tx.Hash)),
			strings.ToLower(strings.TrimSpace(tx.From)),
			strings.ToLower(strings.TrimSpace(tx.To)),
			strings.ToLower(strings.TrimSpace(tx.ContractAddress)),
			strings.TrimSpace(tx.Amount),
			strings.ToLower(strings.TrimSpace(tx.Symbol)),
			strings.ToLower(strings.TrimSpace(tx.Direction)),
		}, "|")
		if _, ok := seen[key]; ok {
			return
		}
		seen[key] = struct{}{}
		merged = append(merged, tx)
	}

	for _, tx := range incoming {
		appendTx(tx)
	}
	for _, tx := range existing {
		appendTx(tx)
	}

	sort.Slice(merged, func(i, j int) bool {
		if merged[i].Timestamp.Equal(merged[j].Timestamp) {
			return merged[i].Hash > merged[j].Hash
		}
		return merged[i].Timestamp.After(merged[j].Timestamp)
	})
	if len(merged) > limit {
		merged = merged[:limit]
	}
	return merged
}

func mergeAssets(existing, incoming []Asset) []Asset {
	if len(existing) == 0 {
		return append([]Asset(nil), incoming...)
	}
	if len(incoming) == 0 {
		return append([]Asset(nil), existing...)
	}

	merged := make([]Asset, 0, len(existing)+len(incoming))
	seen := make(map[string]struct{}, len(existing)+len(incoming))
	appendAsset := func(item Asset) {
		key := strings.ToLower(strings.TrimSpace(item.ContractAddress))
		if key == "" {
			key = "native"
		}
		if _, ok := seen[key]; ok {
			return
		}
		seen[key] = struct{}{}
		merged = append(merged, item)
	}

	for _, item := range incoming {
		appendAsset(item)
	}
	for _, item := range existing {
		appendAsset(item)
	}
	return merged
}

func nonNativeAssetCount(items []Asset) int {
	count := 0
	for _, item := range items {
		if strings.EqualFold(strings.TrimSpace(item.ContractAddress), "native") {
			continue
		}
		if strings.TrimSpace(item.ContractAddress) == "" {
			continue
		}
		count++
	}
	return count
}

func shouldPreserveExistingAssets(chain string, existing, incoming []Asset) bool {
	if !signerLikeEVMChain(chain) {
		return false
	}
	if nonNativeAssetCount(existing) == 0 {
		return false
	}
	return nonNativeAssetCount(incoming) == 0
}

func updateKnownContractsFromData(chain, address string, assets []Asset, history []Transaction) {
	if !usesPersistentCursorChain(chain) {
		return
	}

	seen := make(map[string]struct{}, len(assets)+len(history))
	contracts := make([]string, 0, len(assets)+len(history))
	state := getSlowChainState(chain, address)
	for _, contract := range state.KnownContracts {
		contract = strings.ToLower(strings.TrimSpace(contract))
		if contract == "" || strings.EqualFold(contract, "native") {
			continue
		}
		if _, ok := seen[contract]; ok {
			continue
		}
		seen[contract] = struct{}{}
		contracts = append(contracts, contract)
	}
	for _, item := range assets {
		contract := strings.ToLower(strings.TrimSpace(item.ContractAddress))
		if contract == "" || strings.EqualFold(contract, "native") {
			continue
		}
		if _, ok := seen[contract]; ok {
			continue
		}
		seen[contract] = struct{}{}
		contracts = append(contracts, contract)
	}
	for _, item := range history {
		contract := strings.ToLower(strings.TrimSpace(item.ContractAddress))
		if contract == "" || strings.EqualFold(contract, "native") {
			continue
		}
		if _, ok := seen[contract]; ok {
			continue
		}
		seen[contract] = struct{}{}
		contracts = append(contracts, contract)
	}
	if len(contracts) == 0 {
		return
	}

	updateSlowChainState(chain, address, func(state *slowChainState) {
		state.KnownContracts = contracts
	})
}

type refreshTarget struct {
	chain   string
	address string
}

func defaultDecimalsForChain(chain string) int {
	switch strings.ToLower(strings.TrimSpace(chain)) {
	case "solana", "sui":
		return 9
	case "tron":
		return 6
	case "bitcoin":
		return 8
	case "ethereum", "0g", "base", "bsc", "arbitrum", "optimism", "polygon", "monad", "tempo", "kite":
		return 18
	default:
		return 18
	}
}

func buildRefreshTargets(addrs map[string]string) []refreshTarget {
	seen := make(map[string]struct{})
	targets := make([]refreshTarget, 0, len(addrs))
	add := func(chain, address string) {
		chain = strings.ToLower(strings.TrimSpace(chain))
		address = strings.TrimSpace(address)
		if chain == "" || address == "" {
			return
		}
		key := chain + ":" + address
		if _, ok := seen[key]; ok {
			return
		}
		seen[key] = struct{}{}
		targets = append(targets, refreshTarget{chain: chain, address: address})
	}

	for chain, addr := range addrs {
		c := strings.ToLower(strings.TrimSpace(chain))
		if c == "ethereum" {
			for _, ec := range evmRefreshChains {
				add(ec, addr)
			}
			continue
		}
		add(c, addr)
	}

	return targets
}

func touchCacheEntryLocked(chain, address string, touchedAt time.Time) {
	key := strings.ToLower(strings.TrimSpace(chain)) + ":" + strings.TrimSpace(address)
	if key == ":" {
		return
	}
	entry := globalCache[key]
	if entry.InitializedAt.IsZero() {
		entry.InitializedAt = touchedAt
	}
	if entry.WalletAddress == "" {
		entry.WalletAddress = strings.TrimSpace(address)
	}
	if entry.WalletExplorerURL == "" {
		entry.WalletExplorerURL = ExplorerAddressURL(chain, address)
	}
	globalCache[key] = sanitizeCacheEntry(entry)
}

func latestRefreshTimestamp(entry cacheData) time.Time {
	latest := entry.UpdatedAt
	if entry.HistoryUpdatedAt.After(latest) {
		latest = entry.HistoryUpdatedAt
	}
	return latest
}

func shouldAttemptFastRefresh(chain string, entry cacheData) bool {
	if !supportsFastRefresh(chain) {
		return false
	}
	latest := latestRefreshTimestamp(entry)
	if latest.IsZero() {
		if entry.InitializedAt.IsZero() {
			return false
		}
		return time.Since(entry.InitializedAt) >= staleFastRefreshAfter
	}
	return time.Since(latest) >= staleFastRefreshAfter
}

func claimStartupFastRefresh(chainKey, chain string) bool {
	if !supportsFastRefresh(chain) {
		return false
	}
	startupFastRefreshMu.Lock()
	defer startupFastRefreshMu.Unlock()
	if _, ok := startupFastRefresh[chainKey]; ok {
		return false
	}
	startupFastRefresh[chainKey] = struct{}{}
	return true
}

func supportsFastRefresh(chain string) bool {
	switch strings.ToLower(strings.TrimSpace(chain)) {
	case "ethereum", "base", "bsc", "arbitrum", "monad", "tempo", "solana", "sui", "bitcoin", "tron":
		return true
	default:
		return false
	}
}

func acceptsEmptyFastRefresh(chain string) bool {
	switch strings.ToLower(strings.TrimSpace(chain)) {
	case "tempo":
		return true
	default:
		return false
	}
}

func markRefreshStarted(chainKey string, touchedAt time.Time) {
	ensureCacheLoaded()
	mu.Lock()
	entry := globalCache[chainKey]
	entry.LastRefreshTryAt = touchedAt
	entry.LastRefreshStart = touchedAt
	globalCache[chainKey] = sanitizeCacheEntry(entry)
	mu.Unlock()
	persistGlobalCache()
}

func manualRefreshThrottled(chain, address string, window time.Duration) bool {
	if window <= 0 {
		return false
	}
	ensureCacheLoaded()
	mu.RLock()
	entry, ok := globalCache[strings.ToLower(strings.TrimSpace(chain))+":"+strings.TrimSpace(address)]
	mu.RUnlock()
	if !ok || entry.LastRefreshTryAt.IsZero() {
		return false
	}
	return time.Since(entry.LastRefreshTryAt) < window
}

func RecentRefreshAttempted(chain, address string, window time.Duration) bool {
	return manualRefreshThrottled(chain, address, window)
}

func TouchWalletEntries(addrs map[string]string) {
	ensureCacheLoaded()
	touchedAt := time.Now().UTC()
	targets := buildRefreshTargets(addrs)
	mu.Lock()
	for _, target := range targets {
		touchCacheEntryLocked(target.chain, target.address, touchedAt)
	}
	mu.Unlock()
	persistGlobalCache()
}

func AutoRefreshIntervalSeconds() int {
	return int(autoRefreshInterval / time.Second)
}

func FullRefreshFreshForChain(chain, address string, ttl time.Duration) bool {
	chain = strings.ToLower(strings.TrimSpace(chain))
	address = strings.TrimSpace(address)
	if chain == "" || address == "" {
		return false
	}
	ensureCacheLoaded()
	mu.RLock()
	entry, ok := globalCache[chain+":"+address]
	mu.RUnlock()
	if !ok {
		return false
	}
	updatedAt := latestRefreshTimestamp(entry)
	if updatedAt.IsZero() {
		return false
	}
	return time.Since(updatedAt) < ttl
}

func CacheStateSnapshot() map[string]CacheStateView {
	ensureCacheLoaded()
	mu.RLock()
	defer mu.RUnlock()
	out := make(map[string]CacheStateView, len(globalCache))
	for key, value := range globalCache {
		entry := sanitizeCacheEntry(value)
		parts := strings.SplitN(key, ":", 2)
		view := CacheStateView{
			InitializedAt:     entry.InitializedAt,
			UpdatedAt:         entry.UpdatedAt,
			HistoryUpdatedAt:  entry.HistoryUpdatedAt,
			LastRefreshStart:  entry.LastRefreshStart,
			LastRefreshTryAt:  entry.LastRefreshTryAt,
			LastFastRefreshAt: entry.LastFastRefreshAt,
			AssetCount:        len(entry.Assets),
			HistoryCount:      len(entry.History),
		}
		if len(parts) > 0 {
			view.Chain = parts[0]
		}
		if len(parts) > 1 {
			view.Address = parts[1]
		}
		out[key] = view
	}
	return out
}

func alchemyEnabled() bool {
	switch strings.ToLower(strings.TrimSpace(os.Getenv(disableAlchemyEnv))) {
	case "1", "true", "yes", "on":
		return false
	default:
		return true
	}
}

func publicAssetRPCURL(chain string) string {
	urls := publicAssetRPCURLs(chain)
	if len(urls) == 0 {
		return ""
	}
	return urls[0]
}

func publicAssetRPCURLs(chain string) []string {
	switch strings.ToLower(strings.TrimSpace(chain)) {
	case "ethereum":
		return append([]string(nil), ethereumPublicRPCs...)
	case "0g":
		return []string{zeroGAnkrRPC, zeroGOfficialRPC, zeroGPublicNodeRPC, zeroGOriginStakeRPC}
	case "bsc":
		return append([]string(nil), bscPublicRPCs...)
	case "base":
		return append([]string(nil), basePublicRPCs...)
	case "optimism":
		return append([]string(nil), optimismPublicRPCs...)
	case "arbitrum":
		return append([]string(nil), arbitrumPublicRPCs...)
	case "polygon":
		return append([]string(nil), polygonPublicRPCs...)
	case "monad":
		return append([]string(nil), monadPublicRPCs...)
	case "tempo":
		return append([]string(nil), tempoPublicRPCs...)
	case "kite":
		return append([]string(nil), kitePublicRPCs...)
	case "tron":
		return []string{"https://api.trongrid.io"}
	case "solana":
		return []string{
			"https://solana-rpc.publicnode.com",
			"https://rpc.ankr.com/solana",
			"https://api.mainnet-beta.solana.com",
			"https://api.mainnet.solana.com",
		}
	case "sui":
		return []string{"https://fullnode.mainnet.sui.io"}
	case "sepolia":
		return []string{"https://sepolia.drpc.org"}
	default:
		return nil
	}
}

func alchemyRPCURL(chain string) string {
	if !alchemyEnabled() {
		return ""
	}
	return strings.TrimSpace(os.Getenv(alchemyRPCEnvName(chain)))
}

func assetRPCURL(chain string) string {
	chain = strings.ToLower(strings.TrimSpace(chain))
	if override := strings.TrimSpace(os.Getenv("CLAY_RPC_" + strings.ToUpper(chain))); override != "" {
		return strings.TrimSpace(strings.Split(override, ",")[0])
	}
	if url := publicAssetRPCURL(chain); url != "" {
		return url
	}
	return ""
}

func endpointSupportsAlchemyRPC(endpoint string) bool {
	endpoint = strings.ToLower(strings.TrimSpace(endpoint))
	return strings.Contains(endpoint, ".alchemy.com/")
}

func explorerFallbackEnabled() bool {
	return !strings.EqualFold(strings.TrimSpace(os.Getenv(disableExplorerFallbackEnv)), "1")
}

func shouldUseExplorerFallback(chain string, endpoints []string) bool {
	if !explorerFallbackEnabled() {
		return false
	}
	if len(endpoints) == 0 {
		return false
	}
	return !endpointSupportsAlchemyRPC(endpoints[0])
}

func supportsExplorerEVMFallback(chain string) bool {
	switch strings.ToLower(strings.TrimSpace(chain)) {
	case "ethereum", "base", "bsc", "arbitrum", "kite":
		return true
	default:
		return false
	}
}

func fetchExplorerEVMChainData(chain, address string) ([]Asset, []Transaction, error) {
	switch strings.ToLower(strings.TrimSpace(chain)) {
	case "ethereum":
		return fetchBlockscoutChain("ethereum", "https://eth.blockscout.com/api/v2", address)
	case "base":
		return fetchBlockscoutChain("base", "https://base.blockscout.com/api/v2", address)
	case "bsc":
		return fetchEthplorerChain("bsc", "https://api.binplorer.com", address)
	case "arbitrum":
		return fetchBlockscoutChain("arbitrum", "https://arbitrum.blockscout.com/api/v2", address)
	case "kite":
		return fetchBlockscoutChain("kite", "https://kitescan.ai/api/v2", address)
	default:
		return nil, nil, fmt.Errorf("%s explorer fallback unsupported", chain)
	}
}

func fetchExplorerEVMHistory(chain, address string, limit int) ([]Transaction, error) {
	_, history, err := fetchExplorerEVMChainData(chain, address)
	if err != nil {
		return nil, err
	}
	sort.Slice(history, func(i, j int) bool {
		if history[i].Timestamp.Equal(history[j].Timestamp) {
			return history[i].Hash > history[j].Hash
		}
		return history[i].Timestamp.After(history[j].Timestamp)
	})
	if limit > 0 && len(history) > limit {
		history = history[:limit]
	}
	return history, nil
}

func assetRPCURLs(chain string) []string {
	chain = strings.ToLower(strings.TrimSpace(chain))
	seen := make(map[string]struct{})
	urls := make([]string, 0, 6)
	add := func(url string) {
		url = strings.TrimSpace(url)
		if url == "" {
			return
		}
		if _, ok := seen[url]; ok {
			return
		}
		seen[url] = struct{}{}
		urls = append(urls, url)
	}

	if override := strings.TrimSpace(os.Getenv("CLAY_RPC_" + strings.ToUpper(chain))); override != "" {
		for _, item := range strings.Split(override, ",") {
			add(item)
		}
	}
	for _, url := range publicAssetRPCURLs(chain) {
		add(url)
	}
	return urls
}

// RPCProxyURLs returns the ordered endpoint list used by the sandbox JSON-RPC proxy.
func RPCProxyURLs(chain string) []string {
	chain = strings.ToLower(strings.TrimSpace(chain))
	seen := make(map[string]struct{})
	urls := make([]string, 0, 8)
	add := func(url string) {
		url = strings.TrimSpace(url)
		if url == "" {
			return
		}
		if _, ok := seen[url]; ok {
			return
		}
		seen[url] = struct{}{}
		urls = append(urls, url)
	}
	if override := strings.TrimSpace(os.Getenv("CLAY_RPC_" + strings.ToUpper(chain))); override != "" {
		for _, item := range strings.Split(override, ",") {
			add(item)
		}
	}
	for _, url := range publicAssetRPCURLs(chain) {
		add(url)
	}
	if chain != "0g" && chain != "monad" && chain != "kite" {
		add(alchemyRPCURL(chain))
	}
	return urls
}

func fetchSolanaMeta(url, mint string) int {
	mu.RLock()
	if d, ok := decCache["solana:"+mint]; ok && d > 0 {
		mu.RUnlock()
		return d
	}
	mu.RUnlock()

	res, err := rpcCall(url, "getTokenSupply", []interface{}{mint})
	if err != nil || res["result"] == nil {
		return 9
	}

	result, ok := res["result"].(map[string]interface{})
	if !ok || result["value"] == nil {
		return 9
	}
	value, ok := result["value"].(map[string]interface{})
	if !ok {
		return 9
	}

	dec := 9
	if raw, ok := value["decimals"].(float64); ok && raw >= 0 {
		dec = int(raw)
	}

	mu.Lock()
	decCache["solana:"+mint] = dec
	mu.Unlock()
	return dec
}

func TokenDecimals(chain, contract string) int {
	chain = strings.ToLower(strings.TrimSpace(chain))
	contract = strings.TrimSpace(contract)
	if contract == "" || strings.EqualFold(contract, "native") {
		return defaultDecimalsForChain(chain)
	}

	symbol, decimals := getCachedTokenMeta(chain, contract, "", 0)
	_ = symbol
	if decimals > 0 {
		return decimals
	}

	switch chain {
	case "ethereum", "0g", "base", "bsc", "arbitrum", "optimism", "polygon", "monad", "tempo":
		for _, url := range assetRPCURLs(chain) {
			if url == "" {
				continue
			}
			_, dec := fetchEVMMeta(chain, url, contract)
			if dec > 0 {
				cacheTokenMeta(chain, contract, "", dec)
				return dec
			}
		}
	case "solana":
		if url := assetRPCURL(chain); url != "" {
			if dec := fetchSolanaMeta(url, contract); dec > 0 {
				cacheTokenMeta(chain, contract, "", dec)
				return dec
			}
		}
	case "sui":
		if url := assetRPCURL(chain); url != "" {
			if dec := fetchSuiMeta(url, contract); dec > 0 {
				cacheTokenMeta(chain, contract, "", dec)
				return dec
			}
		}
	}

	return defaultDecimalsForChain(chain)
}

func alchemyRPCEnvName(chain string) string {
	chain = strings.ToUpper(strings.TrimSpace(chain))
	if chain == "" {
		return ""
	}
	return alchemyRPCEnvPrefix + chain
}

// StartAutoRefresh starts the background polling loop for the given multi-chain addresses.
func StartAutoRefresh(addressLookup func() map[string]string) {
	autoRefreshOnce.Do(func() {
		go func() {
			for {
				time.Sleep(autoRefreshInterval)
				RefreshAllAuto(addressLookup())
			}
		}()
	})
}

// RefreshAll refreshes the cache for all supported chains of the given addresses
func RefreshAll(addrs map[string]string) {
	refreshAll(addrs, false, true)
}

// RefreshAllForce refreshes the cache for all supported chains regardless of staleness.
func RefreshAllForce(addrs map[string]string) {
	refreshAll(addrs, true, true)
}

// RefreshAllRequested refreshes all tracked chains for a user-initiated request.
// Repeated requests inside the manual throttle window are ignored per chain.
func RefreshAllRequested(addrs map[string]string) {
	refreshAllRequested(addrs, true)
}

// RefreshAllAuto refreshes lightweight/public-safe chains during the periodic auto loop.
func RefreshAllAuto(addrs map[string]string) {
	refreshAll(addrs, false, true)
}

func refreshAllRequested(addrs map[string]string, includeSlow bool) {
	ensureCacheLoaded()
	startedAt := time.Now()
	defer func() {
		log.Printf("[claw wallet assets] Manual refresh finished in %s (include_slow=%t)", time.Since(startedAt).Round(time.Millisecond), includeSlow)
	}()

	var wg sync.WaitGroup
	for _, target := range buildRefreshTargets(addrs) {
		if !includeSlow && IsNonBlockingRefreshChain(target.chain) {
			continue
		}
		if manualRefreshThrottled(target.chain, target.address, manualRefreshThrottle) {
			log.Printf("[claw wallet assets] Manual refresh throttled for %s/%s (window=%s)", target.chain, target.address, manualRefreshThrottle)
			continue
		}
		wg.Add(1)
		go func(chainName, address string) {
			defer wg.Done()
			runFullRefreshTask(chainName, address, true)
		}(target.chain, target.address)
	}
	wg.Wait()
}

func refreshAll(addrs map[string]string, force bool, includeSlow bool) {
	ensureCacheLoaded()
	startedAt := time.Now()
	defer func() {
		log.Printf("[claw wallet assets] Full refresh finished in %s (force=%t include_slow=%t)", time.Since(startedAt).Round(time.Millisecond), force, includeSlow)
	}()
	var wg sync.WaitGroup
	for chain, addr := range addrs {
		if addr == "" {
			continue
		}
		c := strings.ToLower(chain)
		// 需要注意evm 系列 的地址都是一样的 但是chain不一样 需要区分开来
		if c == "ethereum" {
			for _, ec := range evmRefreshChains {
				if !includeSlow && IsNonBlockingRefreshChain(ec) {
					continue
				}
				wg.Add(1)
				go func(chainName, address string) {
					defer wg.Done()
					runFullRefreshTask(chainName, address, force)
				}(ec, addr)
			}
		} else {
			if !includeSlow && IsNonBlockingRefreshChain(c) {
				continue
			}
			wg.Add(1)
			go func(chainName, address string) {
				defer wg.Done()
				runFullRefreshTask(chainName, address, force)
			}(c, addr)
		}
	}
	wg.Wait()
}

func RefreshOne(chain, address string) {
	refreshOne(chain, address, false)
}

// RefreshOneForce refreshes the cache for a single chain/address regardless of staleness.
func RefreshOneForce(chain, address string) {
	refreshOne(chain, address, true)
}

// RefreshUsageFacts refreshes only history/usage data needed for transaction policy checks.
func RefreshUsageFacts(addrs map[string]string) {
	refreshUsageFacts(addrs, false)
}

// RefreshUsageFactsForChain refreshes only history/usage data for a single chain/address pair.
func RefreshUsageFactsForChain(chain, address string) {
	refreshUsageFactsForChain(chain, address, false)
}

func refreshOne(chain, address string, force bool) {
	ensureCacheLoaded()
	chain = strings.ToLower(strings.TrimSpace(chain))
	address = strings.TrimSpace(address)
	if chain == "" || address == "" {
		return
	}
	if IsNonBlockingRefreshChain(chain) {
		if !tryStartSlowChainRefresh(chain, address) {
			return
		}
		defer finishSlowChainRefresh(chain, address)
	}
	refreshChainCacheFn(chain, address, force)
}

func refreshUsageFacts(addrs map[string]string, force bool) {
	ensureCacheLoaded()
	startedAt := time.Now()
	targets := buildRefreshTargets(addrs)
	defer func() {
		log.Printf("[claw wallet assets] Usage refresh finished in %s (force=%t targets=%d)", time.Since(startedAt).Round(time.Millisecond), force, len(targets))
	}()
	var wg sync.WaitGroup
	for chain, addr := range addrs {
		if addr == "" {
			continue
		}
		c := strings.ToLower(chain)
		if c == "ethereum" {
			for _, ec := range evmRefreshChains {
				wg.Add(1)
				go func(chainName, address string) {
					defer wg.Done()
					refreshHistoryCache(chainName, address, force)
				}(ec, addr)
			}
		} else {
			wg.Add(1)
			go func(chainName, address string) {
				defer wg.Done()
				refreshHistoryCache(chainName, address, force)
			}(c, addr)
		}
	}
	wg.Wait()
}

func refreshUsageFactsForChain(chain, address string, force bool) {
	ensureCacheLoaded()
	startedAt := time.Now()
	defer func() {
		log.Printf("[claw wallet assets] Usage refresh finished in %s (force=%t targets=1 chain=%s)", time.Since(startedAt).Round(time.Millisecond), force, strings.ToLower(strings.TrimSpace(chain)))
	}()
	refreshHistoryCache(chain, address, force)
}

func runFullRefreshTask(chainName, address string, force bool) {
	if IsNonBlockingRefreshChain(chainName) {
		if startedAt, done := WaitForSlowChainRefresh(chainName, address); done != nil {
			<-done
			log.Printf("[claw wallet assets] Full refresh waited for inflight slow chain %s/%s (inflight=%s)", chainName, address, time.Since(startedAt).Round(time.Millisecond))
			return
		}
		if !tryStartSlowChainRefresh(chainName, address) {
			return
		}
		go refreshChainCacheFn(chainName, address, force)
		log.Printf("[claw wallet assets] Full refresh scheduled in background for slow chain %s/%s", chainName, address)
		return
	}

	startedAt := time.Now()
	done := make(chan struct{})
	timedOut := make(chan struct{})
	go func() {
		defer close(done)
		refreshChainCacheFn(chainName, address, force)
		select {
		case <-timedOut:
			log.Printf("[claw wallet assets] Full refresh background completed for %s/%s in %s after wait timeout", chainName, address, time.Since(startedAt).Round(time.Millisecond))
		default:
		}
	}()

	timer := time.NewTimer(fullChainRefreshTimeout)
	defer timer.Stop()

	select {
	case <-done:
	case <-timer.C:
		close(timedOut)
		log.Printf("[claw wallet assets] Full refresh timed out for %s/%s after waiting %s (inflight=%s)", chainName, address, fullChainRefreshTimeout, time.Since(startedAt).Round(time.Millisecond))
	}
}

func latestBlockNumber(endpoints []string) int {
	if len(endpoints) == 0 {
		return 0
	}
	res, err := rpcCallAny(endpoints, "eth_blockNumber", []interface{}{})
	if err != nil {
		return 0
	}
	return monadIntFromHex(stringValue(res["result"]))
}

func maybeAdvancePersistentCursor(chain, address string, head int) {
	if head <= 0 || !usesPersistentCursorChain(chain) {
		return
	}
	updateSlowChainState(chain, address, func(state *slowChainState) {
		if head > state.ContractScanBlock {
			state.ContractScanBlock = head
		}
		if head > state.HistoryScanBlock {
			state.HistoryScanBlock = head
		}
	})
}

func tryFastRefresh(chainName, address, chainKey string) ([]Asset, []Transaction, bool) {
	if !supportsFastRefresh(chainName) {
		return nil, nil, false
	}

	fastAssets, fastHistory, err := fetchFreeChainData(chainName, address)
	if err != nil {
		return nil, nil, false
	}
	if len(fastAssets) == 0 && len(fastHistory) == 0 && !acceptsEmptyFastRefresh(chainName) {
		return nil, nil, false
	}

	now := time.Now()
	mu.Lock()
	entry := globalCache[chainKey]
	entry.Assets = fastAssets
	entry.History = sanitizeCacheEntry(cacheData{History: fastHistory}).History
	entry.UpdatedAt = now
	entry.HistoryUpdatedAt = now
	entry.LastFastRefreshAt = now
	if entry.WalletAddress == "" {
		entry.WalletAddress = address
	}
	if entry.WalletExplorerURL == "" {
		entry.WalletExplorerURL = ExplorerAddressURL(chainName, address)
	}
	globalCache[chainKey] = sanitizeCacheEntry(entry)
	mu.Unlock()

	if signerLikeEVMChain(chainName) {
		updateKnownContractsFromData(chainName, address, fastAssets, fastHistory)
		maybeAdvancePersistentCursor(chainName, address, latestBlockNumber(publicAssetRPCURLs(chainName)))
	}
	persistGlobalCache()
	return fastAssets, fastHistory, true
}

func signerLikeEVMChain(chain string) bool {
	switch strings.ToLower(strings.TrimSpace(chain)) {
	case "ethereum", "0g", "base", "bsc", "arbitrum", "optimism", "polygon", "monad", "kite", "tempo":
		return true
	default:
		return false
	}
}

func refreshChainCache(chainName, address string, force bool) {
	ensureCacheLoaded()
	startedAt := time.Now()
	defer func() {
		if IsNonBlockingRefreshChain(chainName) {
			finishSlowChainRefresh(chainName, address)
		}
	}()
	var assets []Asset
	var history []Transaction
	chainKey := chainName + ":" + address
	markRefreshStarted(chainKey, startedAt.UTC())
	startupFast := claimStartupFastRefresh(chainKey, chainName)

	if !force && !startupFast && cacheFresh(chainKey, defaultRefreshTTL) {
		log.Printf("[claw wallet assets] Skipped full refresh for %s/%s in %s (cache fresh)", chainName, address, time.Since(startedAt).Round(time.Millisecond))
		return
	}

	mu.RLock()
	entry := globalCache[chainKey]
	mu.RUnlock()
	if startupFast || shouldAttemptFastRefresh(chainName, entry) {
		fastStartedAt := time.Now()
		if fastAssets, fastHistory, ok := tryFastRefresh(chainName, address, chainKey); ok {
			for _, a := range fastAssets {
				if a.ContractAddress != "native" {
					go oracle.GetToken(a.Chain, a.ContractAddress, a.Symbol)
					go security.CheckTokenRisk(a.Chain, a.ContractAddress)
				}
			}
			log.Printf("[claw wallet assets] Fast refresh succeeded for %s/%s in %s: %d assets %d txs", chainName, address, time.Since(fastStartedAt).Round(time.Millisecond), len(fastAssets), len(fastHistory))
			return
		}
		log.Printf("[claw wallet assets] Fast refresh unavailable for %s/%s in %s; falling back to public RPC", chainName, address, time.Since(fastStartedAt).Round(time.Millisecond))
	}

	if chainName == "tron" || (!force && (chainName == "solana" || chainName == "sui" || chainName == "bitcoin")) {
		freeStartedAt := time.Now()
		if freeAssets, freeHistory, err := FetchFreeChainData(chainName, address); err == nil {
			assets = freeAssets
			history = freeHistory
			if len(assets) > 0 || len(history) > 0 {
				mu.Lock()
				now := time.Now()
				globalCache[chainKey] = cacheData{
					Assets:            assets,
					History:           history,
					UpdatedAt:         now,
					HistoryUpdatedAt:  now,
					WalletAddress:     address,
					WalletExplorerURL: ExplorerAddressURL(chainName, address),
				}
				mu.Unlock()
				persistGlobalCache()

				for _, a := range assets {
					if a.ContractAddress != "native" {
						go oracle.GetToken(a.Chain, a.ContractAddress, a.Symbol)
						go security.CheckTokenRisk(a.Chain, a.ContractAddress)
					}
				}

				log.Printf("[claw wallet assets] Free RPC stage succeeded for %s/%s in %s", chainName, address, time.Since(freeStartedAt).Round(time.Millisecond))
				log.Printf("[claw wallet assets] Refreshed %s for %s via free RPC in %s: found %d items, %d txs", chainName, address, time.Since(startedAt).Round(time.Millisecond), len(assets), len(history))
				return
			}
			log.Printf("[claw wallet assets] Free RPC stage returned empty data for %s/%s in %s", chainName, address, time.Since(freeStartedAt).Round(time.Millisecond))
		} else {
			log.Printf("[claw wallet assets] Free RPC stage failed for %s/%s in %s: %v", chainName, address, time.Since(freeStartedAt).Round(time.Millisecond), err)
		}
	}

	if signerLikeEVMChain(chainName) {
		var lastErr error
		endpoints := assetRPCURLs(chainName)
		rpcStartedAt := time.Now()
		assets, history, lastErr = fetchEVMChainDataWithFallback(chainName, endpoints, address)
		if lastErr != nil {
			log.Printf("[claw wallet assets] EVM RPC stage failed for %s/%s in %s: %v", chainName, address, time.Since(rpcStartedAt).Round(time.Millisecond), lastErr)
			log.Printf("[claw wallet assets] EVM refresh failed for %s/%s after %s: %v", chainName, address, time.Since(startedAt).Round(time.Millisecond), lastErr)
			return
		}
		log.Printf("[claw wallet assets] EVM RPC stage completed for %s/%s in %s", chainName, address, time.Since(rpcStartedAt).Round(time.Millisecond))
	} else if chainName == "solana" {
		assetsStartedAt := time.Now()
		assets = fetchSolana(assetRPCURLs(chainName), address)
		log.Printf("[claw wallet assets] Solana assets stage completed for %s in %s: %d items", address, time.Since(assetsStartedAt).Round(time.Millisecond), len(assets))
		historyStartedAt := time.Now()
		history = fetchSolanaHistory(address, assetRPCURLs(chainName))
		log.Printf("[claw wallet assets] Solana history stage completed for %s in %s: %d txs", address, time.Since(historyStartedAt).Round(time.Millisecond), len(history))
	} else if chainName == "sui" {
		url := assetRPCURL(chainName)
		assetsStartedAt := time.Now()
		assets = fetchSui(url, address)
		log.Printf("[claw wallet assets] Sui assets stage completed for %s in %s: %d items", address, time.Since(assetsStartedAt).Round(time.Millisecond), len(assets))
		historyStartedAt := time.Now()
		history = fetchSuiHistory(address, url)
		log.Printf("[claw wallet assets] Sui history stage completed for %s in %s: %d txs", address, time.Since(historyStartedAt).Round(time.Millisecond), len(history))
	} else {
		return
	}

	mu.Lock()
	now := time.Now()
	existing := globalCache[chainKey]
	if shouldPreserveExistingAssets(chainName, existing.Assets, assets) {
		assets = mergeAssets(existing.Assets, assets)
	}
	history = mergeHistory(existing.History, history, persistedHistoryLimit)
	updateKnownContractsFromData(chainName, address, assets, history)
	globalCache[chainKey] = cacheData{
		Assets:            assets,
		History:           history,
		UpdatedAt:         now,
		HistoryUpdatedAt:  now,
		WalletAddress:     address,
		WalletExplorerURL: ExplorerAddressURL(chainName, address),
	}
	mu.Unlock()
	persistGlobalCache()

	for _, a := range assets {
		if a.ContractAddress != "native" {
			go oracle.GetToken(a.Chain, a.ContractAddress, a.Symbol)
			go security.CheckTokenRisk(a.Chain, a.ContractAddress)
		}
	}

	log.Printf("[claw wallet assets] Refreshed %s for %s in %s: found %d items, %d txs", chainName, address, time.Since(startedAt).Round(time.Millisecond), len(assets), len(history))
}

func refreshHistoryCache(chainName, address string, force bool) {
	ensureCacheLoaded()
	startedAt := time.Now()
	chainName = strings.ToLower(strings.TrimSpace(chainName))
	address = strings.TrimSpace(address)
	if chainName == "" || address == "" {
		return
	}

	chainKey := chainName + ":" + address
	if !force && historyFresh(chainKey, defaultHistoryRefreshTTL) {
		log.Printf("[claw wallet assets] Skipped history refresh for %s/%s in %s (cache fresh)", chainName, address, time.Since(startedAt).Round(time.Millisecond))
		return
	}

	history, err := fetchHistoryOnlyWithFallback(chainName, address, usageFactsHistoryLimit)
	if err != nil {
		log.Printf("[claw wallet assets] History refresh failed for %s/%s after %s: %v", chainName, address, time.Since(startedAt).Round(time.Millisecond), err)
		return
	}

	mu.Lock()
	existing := globalCache[chainKey]
	existing.History = mergeHistory(existing.History, history, persistedHistoryLimit)
	existing.HistoryUpdatedAt = time.Now()
	if existing.WalletAddress == "" {
		existing.WalletAddress = address
	}
	if existing.WalletExplorerURL == "" {
		existing.WalletExplorerURL = ExplorerAddressURL(chainName, address)
	}
	globalCache[chainKey] = existing
	mu.Unlock()
	updateKnownContractsFromData(chainName, address, existing.Assets, existing.History)
	persistGlobalCache()

	log.Printf("[claw wallet assets] Refreshed history for %s/%s in %s: %d txs", chainName, address, time.Since(startedAt).Round(time.Millisecond), len(history))
}

func supportsFreeChain(chain string) bool {
	switch strings.ToLower(strings.TrimSpace(chain)) {
	case "ethereum", "base", "bsc", "arbitrum", "solana", "sui", "bitcoin":
		return true
	default:
		return false
	}
}

func cacheFresh(cacheKey string, ttl time.Duration) bool {
	ensureCacheLoaded()
	mu.RLock()
	defer mu.RUnlock()
	data, ok := globalCache[cacheKey]
	if !ok || data.UpdatedAt.IsZero() {
		return false
	}
	return time.Since(data.UpdatedAt) < ttl
}

func historyFresh(cacheKey string, ttl time.Duration) bool {
	ensureCacheLoaded()
	mu.RLock()
	defer mu.RUnlock()
	data, ok := globalCache[cacheKey]
	if !ok {
		return false
	}
	updatedAt := data.HistoryUpdatedAt
	if updatedAt.IsZero() {
		updatedAt = data.UpdatedAt
	}
	if updatedAt.IsZero() {
		return false
	}
	return time.Since(updatedAt) < ttl
}

// HistoryFreshForChain reports whether a single chain/address history cache is fresh within ttl.
func HistoryFreshForChain(chain, address string, ttl time.Duration) bool {
	chain = strings.ToLower(strings.TrimSpace(chain))
	address = strings.TrimSpace(address)
	if chain == "" || address == "" {
		return false
	}
	return historyFresh(chain+":"+address, ttl)
}

func fetchHistoryOnlyWithFallback(chain, address string, limit int) ([]Transaction, error) {
	chain = strings.ToLower(strings.TrimSpace(chain))
	address = strings.TrimSpace(address)
	if limit <= 0 {
		limit = usageFactsHistoryLimit
	}
	switch chain {
	case "0g", "kite":
		return fetchStandardEVMHistory(chain, assetRPCURLs(chain), address, limit)
	case "monad":
		return fetchMonadHistory(assetRPCURLs(chain), address, limit)
	case "ethereum", "base", "bsc", "arbitrum", "optimism", "polygon", "tempo", "sepolia":
		endpoints := assetRPCURLs(chain)
		if len(endpoints) == 0 {
			return nil, fmt.Errorf("%s history: no endpoints configured", chain)
		}
		if shouldUseExplorerFallback(chain, endpoints) && supportsExplorerEVMFallback(chain) {
			if history, err := fetchExplorerEVMHistory(chain, address, limit); err == nil && len(history) > 0 {
				return history, nil
			}
		}
		return fetchStandardEVMHistory(chain, endpoints, address, limit)
	case "solana":
		endpoints := assetRPCURLs(chain)
		if len(endpoints) == 0 {
			return nil, fmt.Errorf("solana history: no endpoint configured")
		}
		return fetchSolanaHistory(address, endpoints), nil
	case "sui":
		url := assetRPCURL(chain)
		if strings.TrimSpace(url) == "" {
			return nil, fmt.Errorf("sui history: no endpoint configured")
		}
		return fetchSuiHistory(address, url), nil
	case "bitcoin":
		return fetchBitcoinHistoryAcrossBases(address, "", time.Now().Add(15*time.Second))
	case "tron":
		return fetchTronHistory(address), nil
	default:
		return nil, fmt.Errorf("unsupported chain %q", chain)
	}
}

func fetchEVMChainDataWithFallback(chain string, endpoints []string, address string) ([]Asset, []Transaction, error) {
	if len(endpoints) == 0 {
		return nil, nil, fmt.Errorf("%s rpc: no endpoints configured", chain)
	}

	switch chain {
	case "0g", "kite":
		assetsStartedAt := time.Now()
		assets, err := fetchStandardEVMAssets(chain, endpoints, address)
		if err != nil {
			return nil, nil, err
		}
		log.Printf("[claw wallet assets] EVM assets stage completed for %s/%s via standard RPC in %s: %d items", chain, address, time.Since(assetsStartedAt).Round(time.Millisecond), len(assets))
		historyStartedAt := time.Now()
		history, histErr := fetchStandardEVMHistory(chain, endpoints, address, fullRefreshHistoryLimit)
		if histErr != nil {
			log.Printf("[claw wallet assets] EVM history stage failed for %s/%s via standard RPC in %s: %v", chain, address, time.Since(historyStartedAt).Round(time.Millisecond), histErr)
			return assets, []Transaction{}, nil
		}
		log.Printf("[claw wallet assets] EVM history stage completed for %s/%s via standard RPC in %s: %d txs", chain, address, time.Since(historyStartedAt).Round(time.Millisecond), len(history))
		return assets, history, nil
	case "monad":
		standardAssetsStartedAt := time.Now()
		assets, err := fetchStandardEVMAssets(chain, endpoints, address)
		if err != nil {
			return nil, nil, err
		}
		log.Printf("[claw wallet assets] EVM assets stage completed for %s/%s via standard RPC in %s: %d items", chain, address, time.Since(standardAssetsStartedAt).Round(time.Millisecond), len(assets))
		historyStartedAt := time.Now()
		history, histErr := fetchMonadHistory(endpoints, address, fullRefreshHistoryLimit)
		if histErr != nil {
			log.Printf("[claw wallet assets] EVM history stage failed for %s/%s via monad history fallback in %s: %v", chain, address, time.Since(historyStartedAt).Round(time.Millisecond), histErr)
			return assets, []Transaction{}, nil
		}
		log.Printf("[claw wallet assets] EVM history stage completed for %s/%s via monad history fallback in %s: %d txs", chain, address, time.Since(historyStartedAt).Round(time.Millisecond), len(history))
		return assets, history, nil
	case "tempo":
		assetsStartedAt := time.Now()
		assets, err := fetchTempoAssets(endpoints, address)
		if err != nil {
			return nil, nil, err
		}
		log.Printf("[claw wallet assets] EVM assets stage completed for %s/%s via tempo RPC in %s: %d items", chain, address, time.Since(assetsStartedAt).Round(time.Millisecond), len(assets))
		historyStartedAt := time.Now()
		history, histErr := fetchStandardEVMHistory(chain, endpoints, address, fullRefreshHistoryLimit)
		if histErr != nil {
			log.Printf("[claw wallet assets] EVM history stage failed for %s/%s via standard RPC in %s: %v", chain, address, time.Since(historyStartedAt).Round(time.Millisecond), histErr)
			return assets, []Transaction{}, nil
		}
		log.Printf("[claw wallet assets] EVM history stage completed for %s/%s via standard RPC in %s: %d txs", chain, address, time.Since(historyStartedAt).Round(time.Millisecond), len(history))
		return assets, history, nil
	default:
		if shouldUseExplorerFallback(chain, endpoints) && supportsExplorerEVMFallback(chain) {
			explorerStartedAt := time.Now()
			if assets, history, err := fetchExplorerEVMChainData(chain, address); err == nil && (len(assets) > 0 || len(history) > 0) {
				log.Printf("[claw wallet assets] EVM explorer stage completed for %s/%s in %s: %d assets %d txs", chain, address, time.Since(explorerStartedAt).Round(time.Millisecond), len(assets), len(history))
				return assets, history, nil
			}
			log.Printf("[claw wallet assets] EVM explorer stage unavailable for %s/%s in %s; falling back to standard RPC", chain, address, time.Since(explorerStartedAt).Round(time.Millisecond))
		}

		standardAssetsStartedAt := time.Now()
		assets, err := fetchStandardEVMAssets(chain, endpoints, address)
		if err != nil {
			return nil, nil, err
		}
		log.Printf("[claw wallet assets] EVM assets stage completed for %s/%s via standard RPC in %s: %d items", chain, address, time.Since(standardAssetsStartedAt).Round(time.Millisecond), len(assets))
		standardHistoryStartedAt := time.Now()
		history, histErr := fetchStandardEVMHistory(chain, endpoints, address, fullRefreshHistoryLimit)
		if histErr != nil {
			log.Printf("[claw wallet assets] EVM history stage failed for %s/%s via standard RPC in %s: %v", chain, address, time.Since(standardHistoryStartedAt).Round(time.Millisecond), histErr)
			return assets, []Transaction{}, nil
		}
		log.Printf("[claw wallet assets] EVM history stage completed for %s/%s via standard RPC in %s: %d txs", chain, address, time.Since(standardHistoryStartedAt).Round(time.Millisecond), len(history))
		return assets, history, nil
	}
}

func fetchTempoAssets(endpoints []string, address string) ([]Asset, error) {
	var lastErr error
	for _, endpoint := range endpoints {
		endpoint = strings.TrimSpace(endpoint)
		if endpoint == "" {
			continue
		}
		assets, err := fetchTempoAssetsFromRPC(endpoint, address)
		if err != nil {
			lastErr = err
			continue
		}
		return assets, nil
	}
	if lastErr != nil {
		return nil, lastErr
	}
	return nil, nil
}

func fetchTempoAssetsFromRPC(endpoint, address string) ([]Asset, error) {
	results := make([]Asset, 0, len(tempoTrackedTokens))
	for _, token := range tempoTrackedTokens {
		balance, err := tempoTIP20BalanceOfRPC(endpoint, token.Address, address)
		if err != nil {
			return nil, err
		}
		if balance == nil || balance.Sign() <= 0 {
			continue
		}

		decimals, err := tempoTIP20DecimalsRPC(endpoint, token.Address)
		if err != nil {
			return nil, err
		}
		symbol := token.Symbol
		if fetchedSymbol, err := tempoTIP20StringCallRPC(endpoint, token.Address, "0x95d89b41"); err == nil && strings.TrimSpace(fetchedSymbol) != "" {
			symbol = fetchedSymbol
		}
		cacheTokenMeta("tempo", token.Address, symbol, decimals)

		fValue, _ := new(big.Float).SetInt(balance).Float64()
		divisor := 1.0
		for i := 0; i < decimals; i++ {
			divisor *= 10
		}
		results = append(results, Asset{
			Chain:           "tempo",
			ContractAddress: token.Address,
			Symbol:          symbol,
			BalanceStr:      balance.String(),
			Decimals:        decimals,
			UIBalance:       fValue / divisor,
			ExplorerURL:     ExplorerTokenURL("tempo", token.Address),
		})
	}
	return results, nil
}

func tempoTIP20BalanceOfRPC(endpoint, tokenAddress, holder string) (*big.Int, error) {
	data := "0x70a08231" + tempoEncodeAddress(holder)
	raw, err := tempoEthCallRPC(endpoint, tokenAddress, data)
	if err != nil {
		return nil, err
	}
	return monadBigIntFromHex(raw), nil
}

func tempoTIP20DecimalsRPC(endpoint, tokenAddress string) (int, error) {
	raw, err := tempoEthCallRPC(endpoint, tokenAddress, "0x313ce567")
	if err != nil {
		return 0, err
	}
	value := monadBigIntFromHex(raw)
	if value == nil {
		return 0, fmt.Errorf("tempo decimals returned invalid result")
	}
	return int(value.Int64()), nil
}

func tempoTIP20StringCallRPC(endpoint, tokenAddress, methodID string) (string, error) {
	raw, err := tempoEthCallRPC(endpoint, tokenAddress, methodID)
	if err != nil {
		return "", err
	}
	return tempoDecodeABIString(raw)
}

func tempoEthCallRPC(endpoint, tokenAddress, data string) (string, error) {
	res, err := rpcCall(endpoint, "eth_call", []interface{}{
		map[string]interface{}{
			"to":   tokenAddress,
			"data": data,
		},
		"latest",
	})
	if err != nil {
		return "", err
	}
	raw := stringValue(res["result"])
	if strings.TrimSpace(raw) == "" {
		return "", fmt.Errorf("tempo eth_call returned empty result")
	}
	return raw, nil
}

func tempoEncodeAddress(address string) string {
	address = strings.TrimSpace(strings.TrimPrefix(strings.ToLower(address), "0x"))
	return strings.Repeat("0", 64-len(address)) + address
}

func tempoDecodeABIString(raw string) (string, error) {
	raw = strings.TrimPrefix(strings.TrimSpace(raw), "0x")
	if len(raw) >= 128 {
		offset, ok := new(big.Int).SetString(raw[:64], 16)
		if ok && offset.Int64() == 32 {
			lengthValue, ok := new(big.Int).SetString(raw[64:128], 16)
			if !ok {
				return "", fmt.Errorf("invalid abi string length")
			}
			length := int(lengthValue.Int64())
			start := 128
			end := start + length*2
			if end > len(raw) {
				return "", fmt.Errorf("abi string out of range")
			}
			decoded, err := hex.DecodeString(raw[start:end])
			if err != nil {
				return "", err
			}
			return string(decoded), nil
		}
	}

	decoded, err := hex.DecodeString(raw)
	if err != nil {
		return "", err
	}
	return strings.TrimRight(string(decoded), "\x00"), nil
}

// HistorySnapshot returns all cached transactions across all addresses.
// It normalizes each transaction's Chain based on the cache key to avoid
// mismatches if an upstream fetch reports an unexpected chain string.
func HistorySnapshot() []Transaction {
	return historySnapshotByChain("")
}

// HistorySnapshotByChain returns cached transactions for a specific chain.
// If chain is empty, all chains are returned.
func HistorySnapshotByChain(chain string) []Transaction {
	return historySnapshotByChain(chain)
}

func DailyUsageSnapshot() DailyUsage {
	ensureCacheLoaded()
	mu.RLock()
	defer mu.RUnlock()

	todayStart := time.Now().UTC().Truncate(24 * time.Hour)
	countedTxs := make(map[string]struct{})
	usage := DailyUsage{}

	for key, data := range globalCache {
		parts := strings.SplitN(key, ":", 2)
		cacheChain := strings.ToLower(parts[0])
		historyUpdatedAt := data.HistoryUpdatedAt
		if historyUpdatedAt.IsZero() {
			historyUpdatedAt = data.UpdatedAt
		}
		if historyUpdatedAt.After(usage.UpdatedAt) {
			usage.UpdatedAt = historyUpdatedAt
		}

		for _, tx := range data.History {
			if tx.Timestamp.IsZero() || tx.Timestamp.UTC().Before(todayStart) {
				continue
			}
			if !strings.EqualFold(tx.Status, "success") {
				continue
			}
			if tx.Direction != "" && !strings.EqualFold(tx.Direction, "outgoing") {
				continue
			}

			txKey := cacheChain + ":" + tx.Hash
			if _, ok := countedTxs[txKey]; !ok {
				countedTxs[txKey] = struct{}{}
				usage.TxCount++
			}

			amount, err := strconv.ParseFloat(strings.TrimSpace(tx.Amount), 64)
			if err != nil || amount <= 0 {
				continue
			}

			var (
				price float64
				ok    bool
			)
			contract := strings.TrimSpace(tx.ContractAddress)
			if contract != "" && !strings.EqualFold(contract, "native") {
				price, ok = oracle.GetToken(cacheChain, contract, tx.Symbol)
			} else {
				price, ok = oracle.Get(cacheChain)
			}
			if !ok {
				continue
			}

			usage.SpentUSD += amount * price
		}
	}

	return usage
}

func historySnapshotByChain(chain string) []Transaction {
	ensureCacheLoaded()
	mu.RLock()
	defer mu.RUnlock()

	filter := strings.ToLower(strings.TrimSpace(chain))
	var all []Transaction

	for key, data := range globalCache {
		parts := strings.SplitN(key, ":", 2)
		cacheChain := strings.ToLower(parts[0])
		if filter != "" && cacheChain != filter {
			continue
		}
		for _, tx := range data.History {
			// Ensure tx.Chain matches the cache entry it was found in
			tx.Chain = cacheChain
			all = append(all, tx)
		}
	}
	return all
}

// Snapshot returns the current localized asset cache
func Snapshot() map[string]cacheData {
	ensureCacheLoaded()
	mu.RLock()
	defer mu.RUnlock()

	// Create a safe copy
	out := make(map[string]cacheData)
	for k, v := range globalCache {
		out[k] = v
	}
	return out
}

func ExplorerTxURL(chain, hash string) string {
	chain = strings.ToLower(strings.TrimSpace(chain))
	hash = strings.TrimSpace(hash)
	if chain == "" || hash == "" {
		return ""
	}
	switch chain {
	case "ethereum":
		return "https://etherscan.io/tx/" + hash
	case "0g":
		return "https://chainscan.0g.ai/tx/" + hash
	case "base":
		return "https://basescan.org/tx/" + hash
	case "bsc":
		return "https://bscscan.com/tx/" + hash
	case "solana":
		return "https://solscan.io/tx/" + hash
	case "sui":
		return "https://suivision.xyz/txblock/" + hash
	case "tron":
		return "https://tronscan.org/#/transaction/" + hash
	case "polygon":
		return "https://polygonscan.com/tx/" + hash
	case "arbitrum":
		return "https://arbiscan.io/tx/" + hash
	case "optimism":
		return "https://optimistic.etherscan.io/tx/" + hash
	case "monad":
		return "https://monadvision.com/tx/" + hash
	case "tempo":
		return "https://explore.tempo.xyz/tx/" + hash
	case "kite":
		return "https://kitescan.ai/tx/" + hash
	case "bitcoin":
		return "https://mempool.space/tx/" + hash
	default:
		return ""
	}
}

func ExplorerAddressURL(chain, address string) string {
	chain = strings.ToLower(strings.TrimSpace(chain))
	address = strings.TrimSpace(address)
	if chain == "" || address == "" {
		return ""
	}
	switch chain {
	case "ethereum":
		return "https://etherscan.io/address/" + address
	case "0g":
		return "https://chainscan.0g.ai/address/" + address
	case "base":
		return "https://basescan.org/address/" + address
	case "bsc":
		return "https://bscscan.com/address/" + address
	case "solana":
		return "https://solscan.io/account/" + address
	case "sui":
		return "https://suivision.xyz/account/" + address
	case "tron":
		return "https://tronscan.org/#/address/" + address
	case "polygon":
		return "https://polygonscan.com/address/" + address
	case "arbitrum":
		return "https://arbiscan.io/address/" + address
	case "optimism":
		return "https://optimistic.etherscan.io/address/" + address
	case "monad":
		return "https://monadvision.com/address/" + address
	case "tempo":
		return "https://explore.tempo.xyz/address/" + address
	case "kite":
		return "https://kitescan.ai/address/" + address
	case "bitcoin":
		return "https://mempool.space/address/" + address
	default:
		return ""
	}
}

func ExplorerTokenURL(chain, contractAddress string) string {
	chain = strings.ToLower(strings.TrimSpace(chain))
	contractAddress = strings.TrimSpace(contractAddress)
	if chain == "" || contractAddress == "" || strings.EqualFold(contractAddress, "native") {
		return ""
	}
	switch chain {
	case "ethereum":
		return "https://etherscan.io/token/" + contractAddress
	case "0g":
		return "https://chainscan.0g.ai/address/" + contractAddress
	case "base":
		return "https://basescan.org/token/" + contractAddress
	case "bsc":
		return "https://bscscan.com/token/" + contractAddress
	case "solana":
		return "https://solscan.io/token/" + contractAddress
	case "sui":
		return "https://suivision.xyz/coin/" + contractAddress
	case "tron":
		if isDecimalString(contractAddress) {
			return "https://tronscan.org/#/token10/" + contractAddress
		}
		return "https://tronscan.org/#/token20/" + contractAddress
	case "polygon":
		return "https://polygonscan.com/token/" + contractAddress
	case "arbitrum":
		return "https://arbiscan.io/token/" + contractAddress
	case "optimism":
		return "https://optimistic.etherscan.io/token/" + contractAddress
	case "monad":
		return "https://monadvision.com/token/" + contractAddress
	case "tempo":
		return "https://explore.tempo.xyz/token/" + contractAddress
	case "kite":
		return "https://kitescan.ai/token/" + contractAddress
	default:
		return ""
	}
}

func isDecimalString(s string) bool {
	s = strings.TrimSpace(s)
	if s == "" {
		return false
	}
	for _, r := range s {
		if r < '0' || r > '9' {
			return false
		}
	}
	return true
}

func rpcCall(url, method string, params interface{}) (map[string]interface{}, error) {
	payload := map[string]interface{}{
		"jsonrpc": "2.0",
		"id":      1,
		"method":  method,
		"params":  params,
	}
	b, _ := json.Marshal(payload)
	resp, err := client.Post(url, "application/json", bytes.NewReader(b))
	if err != nil {
		return nil, utils.SanitizeError(err)
	}
	defer resp.Body.Close()

	if resp.StatusCode >= 400 {
		respBody, _ := io.ReadAll(io.LimitReader(resp.Body, 2048))
		return nil, fmt.Errorf("rpc %s returned %d: %s", method, resp.StatusCode, strings.TrimSpace(string(respBody)))
	}

	var res map[string]interface{}
	if err := json.NewDecoder(resp.Body).Decode(&res); err != nil {
		return nil, err
	}
	if rpcErr, ok := res["error"].(map[string]interface{}); ok && rpcErr != nil {
		return nil, fmt.Errorf("rpc %s returned %s", method, strings.TrimSpace(stringValue(rpcErr["message"])))
	}
	return res, nil
}

func fetchEVMBlocksBatch(endpoint string, fromBlock, toBlock int) map[int]map[string]interface{} {
	endpoint = strings.TrimSpace(endpoint)
	if endpoint == "" || toBlock < fromBlock {
		return nil
	}

	type batchItem struct {
		JSONRPC string        `json:"jsonrpc"`
		ID      string        `json:"id"`
		Method  string        `json:"method"`
		Params  []interface{} `json:"params"`
	}
	requests := make([]batchItem, 0, toBlock-fromBlock+1)
	for blockNumber := fromBlock; blockNumber <= toBlock; blockNumber++ {
		requests = append(requests, batchItem{
			JSONRPC: "2.0",
			ID:      fmt.Sprintf("%d", blockNumber),
			Method:  "eth_getBlockByNumber",
			Params:  []interface{}{fmt.Sprintf("0x%x", blockNumber), true},
		})
	}

	data, err := json.Marshal(requests)
	if err != nil {
		return nil
	}
	resp, err := client.Post(endpoint, "application/json", bytes.NewBuffer(data))
	if err != nil {
		return nil
	}
	defer resp.Body.Close()
	if resp.StatusCode >= 400 {
		return nil
	}

	var responses []struct {
		ID     string                 `json:"id"`
		Result map[string]interface{} `json:"result"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&responses); err != nil {
		return nil
	}

	out := make(map[int]map[string]interface{}, len(responses))
	for _, item := range responses {
		blockNumber, err := strconv.Atoi(strings.TrimSpace(item.ID))
		if err != nil || item.Result == nil {
			continue
		}
		out[blockNumber] = item.Result
	}
	return out
}

func fetchEVMBlocksBatchAny(endpoints []string, fromBlock, toBlock int) map[int]map[string]interface{} {
	if toBlock < fromBlock {
		return nil
	}

	total := toBlock - fromBlock + 1
	if total <= 0 {
		return nil
	}

	result := make(map[int]map[string]interface{}, total)
	seen := make(map[string]struct{}, len(endpoints))
	ordered := make([]string, 0, len(endpoints))
	for _, endpoint := range endpoints {
		endpoint = strings.TrimSpace(endpoint)
		if endpoint == "" {
			continue
		}
		if _, ok := seen[endpoint]; ok {
			continue
		}
		seen[endpoint] = struct{}{}
		ordered = append(ordered, endpoint)
	}
	if len(ordered) == 0 {
		return nil
	}

	for _, endpoint := range ordered {
		batch := fetchEVMBlocksBatch(endpoint, fromBlock, toBlock)
		if len(batch) == 0 {
			continue
		}
		for blockNumber, block := range batch {
			if block == nil {
				continue
			}
			result[blockNumber] = block
		}
		if len(result) >= total {
			break
		}
	}
	if len(result) == 0 {
		return nil
	}
	return result
}

func fetchEVM(chain, url, address string) ([]Asset, error) {
	var results []Asset

	// 1. Fetch Native Balance
	rNative, err := rpcCall(url, "eth_getBalance", []interface{}{address, "latest"})
	if err != nil {
		return nil, err
	}
	if rNative["result"] != nil {
		balHex := strings.TrimPrefix(rNative["result"].(string), "0x")
		val := new(big.Int)
		val.SetString(balHex, 16)
		fVal, _ := new(big.Float).SetInt(val).Float64()
		results = append(results, Asset{
			Chain:           chain,
			ContractAddress: "native",
			Symbol:          getNativeSymbol(chain),
			BalanceStr:      val.String(),
			Decimals:        18,
			UIBalance:       fVal / 1e18,
			ExplorerURL:     ExplorerAddressURL(chain, address),
		})
	}

	// 2. Fetch Token Balances
	res, err := rpcCall(url, "alchemy_getTokenBalances", []string{address})
	if err != nil {
		return nil, err
	}

	resultMap, ok := res["result"].(map[string]interface{})
	if !ok || resultMap["tokenBalances"] == nil {
		return nil, fmt.Errorf("alchemy_getTokenBalances returned no tokenBalances field")
	}

	tb, ok := resultMap["tokenBalances"].([]interface{})
	if !ok {
		return nil, fmt.Errorf("alchemy_getTokenBalances returned malformed tokenBalances")
	}

	for _, t := range tb {
		tmap := t.(map[string]interface{})
		contract := tmap["contractAddress"].(string)
		balStr := tmap["tokenBalance"].(string)

		if balStr == "0x0" || balStr == "0x0000000000000000000000000000000000000000000000000000000000000000" {
			continue
		}

		val := new(big.Int)
		val.SetString(strings.TrimPrefix(balStr, "0x"), 16)
		fVal, _ := new(big.Float).SetInt(val).Float64()

		symbol, dec := fetchEVMMeta(chain, url, contract)

		divisor := 1.0
		for i := 0; i < dec; i++ {
			divisor *= 10
		}

		results = append(results, Asset{
			Chain:           chain,
			ContractAddress: contract,
			Symbol:          symbol,
			BalanceStr:      val.String(),
			Decimals:        dec,
			UIBalance:       fVal / divisor,
			ExplorerURL:     ExplorerTokenURL(chain, contract),
		})
	}
	return results, nil
}

func getNativeSymbol(chain string) string {
	switch chain {
	case "0g":
		return "0G"
	case "ethereum", "base", "arbitrum", "optimism":
		return "ETH"
	case "bsc":
		return "BNB"
	case "polygon":
		return "MATIC"
	case "monad":
		return "MON"
	case "tempo":
		return "USD"
	case "kite":
		return "KITE"
	case "bitcoin":
		return "BTC"
	default:
		return "NATIVE"
	}
}

func suppressNativeBalanceDisplay(chain string) bool {
	return strings.EqualFold(strings.TrimSpace(chain), "tempo")
}

func fetchEVMMeta(chain, url, contract string) (string, int) {
	k := chain + ":" + contract
	mu.RLock()
	sym, ok1 := symCache[k]
	dec, ok2 := decCache[k]
	mu.RUnlock()

	if ok1 && ok2 {
		return sym, dec
	}

	res, err := rpcCall(url, "alchemy_getTokenMetadata", []string{contract})
	if err != nil || res["result"] == nil {
		return "UNKNOWN", 18
	}

	meta := res["result"].(map[string]interface{})

	s := "UNKNOWN"
	if val, ok := meta["symbol"].(string); ok {
		s = val
	}

	d := 18
	if val, ok := meta["decimals"].(float64); ok {
		d = int(val)
	} else if valStr, ok := meta["decimals"].(string); ok {
		// Sometimes returned as hex or string
		if v, err := strconv.ParseInt(strings.TrimPrefix(valStr, "0x"), 16, 64); err == nil {
			d = int(v)
		}
	}

	mu.Lock()
	symCache[k] = s
	decCache[k] = d
	mu.Unlock()

	return s, d
}

func fetchSolana(endpoints []string, address string) []Asset {
	var results []Asset
	if len(endpoints) == 0 {
		return results
	}

	// 1. Native balance
	rNative, err := rpcCallAny(endpoints, "getBalance", []interface{}{address})
	if err == nil && rNative["result"] != nil {
		if res, ok := rNative["result"].(map[string]interface{}); ok {
			if val, ok := res["value"].(float64); ok {
				results = append(results, Asset{
					Chain: "solana", ContractAddress: "native", Symbol: "SOL",
					BalanceStr: fmt.Sprintf("%.0f", val), Decimals: 9, UIBalance: val / 1e9, ExplorerURL: ExplorerAddressURL("solana", address),
				})
			}
		}
	}

	// 2. Token Balances (Legacy + Token-2022)
	pids := []string{"TokenkegQfeZyiNwAJbNbGKPFXCWuBvf9Ss623VQ5DA", "TokenzQ9K64P2LRvS4dgSYTyc9VkvY16HguDAWExLV2"}
	for _, pid := range pids {
		params := []interface{}{
			address,
			map[string]string{"programId": pid},
			map[string]string{"encoding": "jsonParsed"},
		}

		res, err := rpcCallAny(endpoints, "getTokenAccountsByOwner", params)
		if err != nil || res["result"] == nil {
			continue
		}

		resMap, ok := res["result"].(map[string]interface{})
		if !ok || resMap["value"] == nil {
			continue
		}

		accounts := resMap["value"].([]interface{})
		for _, accRaw := range accounts {
			acc := accRaw.(map[string]interface{})["account"].(map[string]interface{})
			data := acc["data"].(map[string]interface{})["parsed"].(map[string]interface{})["info"].(map[string]interface{})

			mint := data["mint"].(string)
			tAmt := data["tokenAmount"].(map[string]interface{})
			amountStr := tAmt["amount"].(string)
			uiAmt, _ := strconv.ParseFloat(tAmt["uiAmountString"].(string), 64)
			dec := int(tAmt["decimals"].(float64))

			if amountStr == "0" {
				continue
			}

			cacheTokenMeta("solana", mint, "SPL-Token", dec)

			results = append(results, Asset{
				Chain:           "solana",
				ContractAddress: mint,
				Symbol:          "SPL-Token",
				BalanceStr:      amountStr,
				Decimals:        dec,
				UIBalance:       uiAmt,
				ExplorerURL:     ExplorerTokenURL("solana", mint),
			})
		}
	}

	return results
}

func fetchSui(url, address string) []Asset {
	var results []Asset
	res, err := rpcCall(url, "suix_getAllBalances", []string{address})
	if err != nil || res["result"] == nil {
		return results
	}

	balances := res["result"].([]interface{})
	for _, bRaw := range balances {
		b := bRaw.(map[string]interface{})
		coinType := b["coinType"].(string)
		totalBal := b["totalBalance"].(string)

		if totalBal == "0" {
			continue
		}

		parts := strings.Split(coinType, "::")
		symbol := "SUI-Coin"
		if len(parts) > 2 {
			symbol = parts[2]
		} else if coinType == "0x2::sui::SUI" {
			symbol = "SUI"
		}

		dec := fetchSuiMeta(url, coinType)

		fBal, _ := strconv.ParseFloat(totalBal, 64)
		divisor := 1.0
		for i := 0; i < dec; i++ {
			divisor *= 10
		}

		addr := coinType
		if coinType == "0x2::sui::SUI" {
			addr = "native"
		}
		cacheTokenMeta("sui", addr, symbol, dec)

		results = append(results, Asset{
			Chain:           "sui",
			ContractAddress: addr,
			Symbol:          symbol,
			BalanceStr:      totalBal,
			Decimals:        dec,
			UIBalance:       fBal / divisor,
			ExplorerURL: func() string {
				if addr == "native" {
					return ExplorerAddressURL("sui", address)
				}
				return ExplorerTokenURL("sui", addr)
			}(),
		})
	}

	return results
}

func fetchSuiMeta(url, coinType string) int {
	if coinType == "0x2::sui::SUI" {
		return 9
	}
	mu.RLock()
	d, ok := decCache["sui:"+coinType]
	mu.RUnlock()
	if ok {
		return d
	}

	res, err := rpcCall(url, "suix_getCoinMetadata", []string{coinType})
	dec := 9
	if err == nil && res["result"] != nil {
		meta := res["result"].(map[string]interface{})
		if val, ok := meta["decimals"].(float64); ok {
			dec = int(val)
		}
	}

	mu.Lock()
	decCache["sui:"+coinType] = dec
	mu.Unlock()
	return dec
}

func fetchEVMHistory(chain, endpoint, address string) ([]Transaction, error) {
	res, err := rpcCall(endpoint, "alchemy_getAssetTransfers", []interface{}{
		map[string]interface{}{
			"fromBlock":        "0x0",
			"toBlock":          "latest",
			"fromAddress":      address,
			"category":         []string{"external", "erc20"},
			"excludeZeroValue": true,
			"maxCount":         "0x32",
			"withMetadata":     true,
		},
	})
	if err != nil {
		return nil, err
	}
	rawResult, _ := res["result"].(map[string]interface{})
	transfers := asSlice(rawResult["transfers"])

	var txs []Transaction

	// Collect missing block numbers for batch query if metadata is absent
	missingBlocks := make(map[string]struct{})
	for _, entry := range transfers {
		item, _ := entry.(map[string]interface{})
		if item == nil {
			continue
		}
		metadata, _ := item["metadata"].(map[string]interface{})
		blockNum := stringValue(item["blockNum"])
		if strings.TrimSpace(stringValue(metadata["blockTimestamp"])) == "" {
			if blockNum != "" {
				missingBlocks[blockNum] = struct{}{}
			}
		}
	}

	blockTimestamps := make(map[string]int64)
	if len(missingBlocks) > 0 {
		var batchReq []map[string]interface{}
		idx := 1
		for b := range missingBlocks {
			batchReq = append(batchReq, map[string]interface{}{
				"jsonrpc": "2.0", "id": b, "method": "eth_getBlockByNumber",
				"params": []interface{}{b, false},
			})
			idx++
		}
		if batchData, err := json.Marshal(batchReq); err == nil {
			if bResp, err := client.Post(endpoint, "application/json", bytes.NewBuffer(batchData)); err == nil {
				defer bResp.Body.Close()
				var bRes []struct {
					ID     string `json:"id"`
					Result struct {
						Timestamp string `json:"timestamp"`
					} `json:"result"`
				}
				json.NewDecoder(bResp.Body).Decode(&bRes)
				for _, b := range bRes {
					if b.Result.Timestamp != "" {
						// parse hex timestamp
						tsHex := strings.TrimPrefix(b.Result.Timestamp, "0x")
						if tv, err := strconv.ParseInt(tsHex, 16, 64); err == nil {
							blockTimestamps[b.ID] = tv
						}
					}
				}
			}
		}
	}

	for _, entry := range transfers {
		t, _ := entry.(map[string]interface{})
		if t == nil {
			continue
		}
		var ts time.Time
		metadata, _ := t["metadata"].(map[string]interface{})
		blockNum := stringValue(t["blockNum"])
		if blockTimestamp := strings.TrimSpace(stringValue(metadata["blockTimestamp"])); blockTimestamp != "" {
			ts, _ = time.Parse(time.RFC3339, blockTimestamp)
		} else if tv, ok := blockTimestamps[blockNum]; ok {
			ts = time.Unix(tv, 0)
		} else {
			ts = time.Now() // fallback
		}

		valueStr := strings.TrimSpace(stringValue(t["value"]))
		if valueStr == "" {
			valueStr = "0"
		}

		txs = append(txs, Transaction{
			Chain:  chain,
			Hash:   stringValue(t["hash"]),
			From:   stringValue(t["from"]),
			To:     stringValue(t["to"]),
			Amount: valueStr,
			Symbol: stringValue(t["asset"]),
			ContractAddress: func() string {
				if rawContract, _ := t["rawContract"].(map[string]interface{}); rawContract != nil {
					if addr := stringValue(rawContract["address"]); addr != "" {
						return addr
					}
				}
				return "native"
			}(),
			Direction:   "outgoing",
			Timestamp:   ts,
			Status:      "success",
			ExplorerURL: ExplorerTxURL(chain, stringValue(t["hash"])),
		})
	}
	return txs, nil
}

func fetchSolanaHistory(address string, endpoints []string) []Transaction {
	if len(endpoints) == 0 {
		return nil
	}

	signatureRes, err := rpcCallAny(endpoints, "getSignaturesForAddress", []interface{}{address, map[string]interface{}{"limit": 100}})
	if err != nil || signatureRes["result"] == nil {
		return nil
	}

	signatureRows := asSlice(signatureRes["result"])
	if len(signatureRows) == 0 {
		return nil
	}

	type signatureRow struct {
		Signature string
		BlockTime int64
	}

	rows := make([]signatureRow, 0, len(signatureRows))
	fallbackBlockTime := make(map[string]int64, len(signatureRows))
	for _, item := range signatureRows {
		row, _ := item.(map[string]interface{})
		if row == nil {
			continue
		}
		signature := strings.TrimSpace(stringValue(row["signature"]))
		if signature == "" {
			continue
		}
		blockTime := int64Value(row["blockTime"])
		rows = append(rows, signatureRow{Signature: signature, BlockTime: blockTime})
		fallbackBlockTime[signature] = blockTime
	}

	var txs []Transaction
	for _, s := range rows {
		txRes, err := rpcCallAny(endpoints, "getTransaction", []interface{}{
			s.Signature,
			map[string]interface{}{
				"encoding":                       "jsonParsed",
				"maxSupportedTransactionVersion": 0,
			},
		})
		if err != nil {
			txs = append(txs, Transaction{
				Chain:           "solana",
				Hash:            s.Signature,
				From:            "multiple",
				To:              address,
				Amount:          "0",
				Symbol:          "SOL",
				ContractAddress: "native",
				Direction:       "incoming",
				Timestamp:       time.Unix(s.BlockTime, 0),
				Status:          "success",
				ExplorerURL:     ExplorerTxURL("solana", s.Signature),
			})
			continue
		}

		result, _ := txRes["result"].(map[string]interface{})
		if result == nil {
			txs = append(txs, Transaction{
				Chain:           "solana",
				Hash:            s.Signature,
				From:            "multiple",
				To:              address,
				Amount:          "0",
				Symbol:          "SOL",
				ContractAddress: "native",
				Direction:       "incoming",
				Timestamp:       time.Unix(s.BlockTime, 0),
				Status:          "success",
				ExplorerURL:     ExplorerTxURL("solana", s.Signature),
			})
			continue
		}
		txs = append(txs, parseSolanaTransaction(address, s.Signature, fallbackBlockTime[s.Signature], result)...)
	}
	return txs
}

func fetchSuiHistory(address, url string) []Transaction {
	allDigests := make([]string, 0, 100)
	seenDigests := make(map[string]struct{}, 100)
	filters := []map[string]interface{}{
		{"FromAddress": address},
		{"ToAddress": address},
	}

	for _, filter := range filters {
		body := map[string]interface{}{
			"jsonrpc": "2.0", "id": 1, "method": "suix_queryTransactionBlocks",
			"params": []interface{}{
				map[string]interface{}{
					"filter":  filter,
					"options": map[string]interface{}{"showTimestamp": true},
				},
				nil,
				50,
				true,
			},
		}
		data, _ := json.Marshal(body)
		resp, err := client.Post(url, "application/json", bytes.NewBuffer(data))
		if err != nil {
			continue
		}
		bodyBytes, _ := io.ReadAll(resp.Body)
		resp.Body.Close()

		var res struct {
			Result struct {
				Data []struct {
					Digest string `json:"digest"`
				} `json:"data"`
			} `json:"result"`
		}
		if err := json.Unmarshal(bodyBytes, &res); err != nil {
			log.Printf("[claw wallet sandbox] Sui history inner parse error: %v", err)
			continue
		}

		for _, d := range res.Result.Data {
			digest := strings.TrimSpace(d.Digest)
			if digest == "" {
				continue
			}
			if _, ok := seenDigests[digest]; ok {
				continue
			}
			seenDigests[digest] = struct{}{}
			allDigests = append(allDigests, digest)
		}
	}

	log.Printf("[claw wallet sandbox] Sui history digests for %s: %d", address, len(allDigests))

	if len(allDigests) == 0 {
		return nil
	}

	metaBody := map[string]interface{}{
		"jsonrpc": "2.0", "id": 1, "method": "sui_multiGetTransactionBlocks",
		"params": []interface{}{
			allDigests,
			map[string]interface{}{
				"showTimestamp":      true,
				"showInput":          true,
				"showEffects":        true,
				"showBalanceChanges": true,
			},
		},
	}
	metaData, _ := json.Marshal(metaBody)
	mResp, err := client.Post(url, "application/json", bytes.NewBuffer(metaData))
	if err != nil {
		return nil
	}
	defer mResp.Body.Close()

	var mRes struct {
		Result []map[string]interface{} `json:"result"`
	}
	json.NewDecoder(mResp.Body).Decode(&mRes)

	var txs []Transaction
	for _, raw := range mRes.Result {
		txs = append(txs, parseSuiTransaction(address, url, raw)...)
	}
	return txs
}

func parseSolanaTransaction(address, hash string, fallbackBlockTime int64, result map[string]interface{}) []Transaction {
	meta, _ := result["meta"].(map[string]interface{})
	if meta == nil {
		return nil
	}

	status := "success"
	if meta["err"] != nil {
		status = "failed"
	}

	blockTime := int64Value(result["blockTime"])
	if blockTime <= 0 {
		blockTime = fallbackBlockTime
	}
	ts := time.Now()
	if blockTime > 0 {
		ts = time.Unix(blockTime, 0)
	}

	txObj, _ := result["transaction"].(map[string]interface{})
	msg, _ := txObj["message"].(map[string]interface{})
	accountKeys := asSlice(msg["accountKeys"])
	addressIdx, signer := solanaAccountIndexAndSigner(accountKeys, address)

	var txs []Transaction

	preBalances := asSlice(meta["preBalances"])
	postBalances := asSlice(meta["postBalances"])
	fee := int64Value(meta["fee"])
	if addressIdx >= 0 && addressIdx < len(preBalances) && addressIdx < len(postBalances) {
		pre := int64Value(preBalances[addressIdx])
		post := int64Value(postBalances[addressIdx])
		outLamports := pre - post - fee
		if outLamports > 0 {
			txs = append(txs, Transaction{
				Chain:           "solana",
				Hash:            hash,
				From:            address,
				To:              "multiple",
				Amount:          formatAmountFromInt64(outLamports, 9),
				Symbol:          "SOL",
				ContractAddress: "native",
				Direction:       "outgoing",
				Timestamp:       ts,
				Status:          status,
			})
		} else if received := post - pre; received > 0 {
			txs = append(txs, Transaction{
				Chain:           "solana",
				Hash:            hash,
				From:            "multiple",
				To:              address,
				Amount:          formatAmountFromInt64(received, 9),
				Symbol:          "SOL",
				ContractAddress: "native",
				Direction:       "incoming",
				Timestamp:       ts,
				Status:          status,
				ExplorerURL:     ExplorerTxURL("solana", hash),
			})
		}
	}

	preTokens := parseSolanaOwnedTokenBalances(meta["preTokenBalances"], address)
	postTokens := parseSolanaOwnedTokenBalances(meta["postTokenBalances"], address)
	for mint, postInfo := range postTokens {
		if _, ok := preTokens[mint]; !ok {
			preTokens[mint] = solanaTokenBalance{Raw: big.NewInt(0), Decimals: postInfo.Decimals}
		}
	}
	for mint, preInfo := range preTokens {
		postInfo, ok := postTokens[mint]
		if !ok {
			postInfo = solanaTokenBalance{Raw: big.NewInt(0), Decimals: preInfo.Decimals}
		}
		delta := new(big.Int).Sub(postInfo.Raw, preInfo.Raw)
		if delta.Sign() == 0 {
			continue
		}
		decimals := preInfo.Decimals
		if postInfo.Decimals > 0 {
			decimals = postInfo.Decimals
		}
		symbol, _ := getCachedTokenMeta("solana", mint, "SPL-Token", decimals)
		direction := "incoming"
		amount := new(big.Int).Set(delta)
		from := "multiple"
		to := address
		if delta.Sign() < 0 {
			direction = "outgoing"
			amount.Neg(amount)
			from = address
			to = "multiple"
		}
		txs = append(txs, Transaction{
			Chain:           "solana",
			Hash:            hash,
			From:            from,
			To:              to,
			Amount:          formatAmountFromBigInt(amount, decimals),
			Symbol:          symbol,
			ContractAddress: mint,
			Direction:       direction,
			Timestamp:       ts,
			Status:          status,
			ExplorerURL:     ExplorerTxURL("solana", hash),
		})
	}

	if len(txs) == 0 && signer {
		txs = append(txs, Transaction{
			Chain:           "solana",
			Hash:            hash,
			From:            address,
			To:              "multiple",
			Amount:          "0",
			Symbol:          "SOL",
			ContractAddress: "native",
			Direction:       "outgoing",
			Timestamp:       ts,
			Status:          status,
			ExplorerURL:     ExplorerTxURL("solana", hash),
		})
	}

	return txs
}

func parseSuiTransaction(address, url string, raw map[string]interface{}) []Transaction {
	digest := stringValue(raw["digest"])
	ms := int64Value(raw["timestampMs"])
	ts := time.Now()
	if ms > 0 {
		ts = time.Unix(0, ms*int64(time.Millisecond))
	}

	status := "success"
	if effects, ok := raw["effects"].(map[string]interface{}); ok {
		if st, ok := effects["status"].(map[string]interface{}); ok {
			if s := strings.ToLower(strings.TrimSpace(stringValue(st["status"]))); s != "" {
				status = s
			}
		}
	}

	from := address
	if txObj, ok := raw["transaction"].(map[string]interface{}); ok {
		if data, ok := txObj["data"].(map[string]interface{}); ok {
			if sender := strings.TrimSpace(stringValue(data["sender"])); sender != "" {
				from = sender
			}
		}
	}

	var txs []Transaction
	for _, item := range asSlice(raw["balanceChanges"]) {
		change, _ := item.(map[string]interface{})
		if change == nil || !strings.EqualFold(suiOwnerAddress(change["owner"]), address) {
			continue
		}
		rawAmt := bigIntValue(change["amount"])
		if rawAmt == nil || rawAmt.Sign() == 0 {
			continue
		}

		coinType := strings.TrimSpace(stringValue(change["coinType"]))
		if coinType == "" {
			continue
		}

		symbol := suiSymbolFromCoinType(coinType)
		contract := coinType
		decimals := 9
		if coinType == "0x2::sui::SUI" {
			contract = "native"
		} else {
			decimals = fetchSuiMeta(url, coinType)
		}
		cacheTokenMeta("sui", contract, symbol, decimals)

		direction := "incoming"
		fromAddr := "multiple"
		toAddr := address
		amount := new(big.Int).Set(rawAmt)
		if rawAmt.Sign() < 0 {
			direction = "outgoing"
			amount.Abs(amount)
			fromAddr = from
			toAddr = "multiple"
		}
		txs = append(txs, Transaction{
			Chain:           "sui",
			Hash:            digest,
			From:            fromAddr,
			To:              toAddr,
			Amount:          formatAmountFromBigInt(amount, decimals),
			Symbol:          symbol,
			ContractAddress: contract,
			Direction:       direction,
			Timestamp:       ts,
			Status:          status,
			ExplorerURL:     ExplorerTxURL("sui", digest),
		})
	}

	if len(txs) == 0 {
		txs = append(txs, Transaction{
			Chain:           "sui",
			Hash:            digest,
			From:            from,
			To:              "multiple",
			Amount:          "0",
			Symbol:          "SUI",
			ContractAddress: "native",
			Direction:       "outgoing",
			Timestamp:       ts,
			Status:          status,
			ExplorerURL:     ExplorerTxURL("sui", digest),
		})
	}

	return txs
}

type solanaTokenBalance struct {
	Raw      *big.Int
	Decimals int
}

func parseSolanaOwnedTokenBalances(raw interface{}, owner string) map[string]solanaTokenBalance {
	out := make(map[string]solanaTokenBalance)
	for _, item := range asSlice(raw) {
		entry, _ := item.(map[string]interface{})
		if entry == nil || !strings.EqualFold(stringValue(entry["owner"]), owner) {
			continue
		}

		mint := strings.TrimSpace(stringValue(entry["mint"]))
		if mint == "" {
			continue
		}

		uiAmount, _ := entry["uiTokenAmount"].(map[string]interface{})
		decimals := int(int64Value(uiAmount["decimals"]))
		amount := bigIntValue(uiAmount["amount"])
		if amount == nil {
			amount = big.NewInt(0)
		}

		cacheTokenMeta("solana", mint, "SPL-Token", decimals)
		current := out[mint]
		if current.Raw == nil {
			current.Raw = big.NewInt(0)
		}
		current.Raw.Add(current.Raw, amount)
		if decimals > 0 {
			current.Decimals = decimals
		}
		out[mint] = current
	}
	return out
}

func solanaAccountIndexAndSigner(accountKeys []interface{}, address string) (int, bool) {
	addressIdx := -1
	signer := false
	for i, item := range accountKeys {
		switch v := item.(type) {
		case string:
			if strings.EqualFold(v, address) {
				addressIdx = i
				if i == 0 {
					signer = true
				}
			}
		case map[string]interface{}:
			pubkey := stringValue(v["pubkey"])
			if !strings.EqualFold(pubkey, address) {
				continue
			}
			addressIdx = i
			if s, ok := v["signer"].(bool); ok && s {
				signer = true
			}
		}
	}
	return addressIdx, signer
}

func cacheTokenMeta(chain, contract, symbol string, decimals int) {
	contract = strings.TrimSpace(contract)
	if contract == "" {
		return
	}
	key := strings.ToLower(chain + ":" + contract)
	changed := false
	mu.Lock()
	if symbol != "" {
		symbol = strings.TrimSpace(symbol)
		if symCache[key] != symbol {
			symCache[key] = symbol
			changed = true
		}
	}
	if decimals > 0 {
		if decCache[key] != decimals {
			decCache[key] = decimals
			changed = true
		}
	}
	mu.Unlock()
	if changed {
		persistGlobalCache()
	}
}

func getCachedTokenMeta(chain, contract, fallbackSymbol string, fallbackDecimals int) (string, int) {
	key := strings.ToLower(chain + ":" + strings.TrimSpace(contract))
	mu.RLock()
	symbol, symOK := symCache[key]
	decimals, decOK := decCache[key]
	mu.RUnlock()
	if !symOK || symbol == "" {
		symbol = fallbackSymbol
	}
	if !decOK || decimals <= 0 {
		decimals = fallbackDecimals
	}
	return symbol, decimals
}

func asSlice(v interface{}) []interface{} {
	if out, ok := v.([]interface{}); ok {
		return out
	}
	return nil
}

func stringValue(v interface{}) string {
	if v == nil {
		return ""
	}
	switch val := v.(type) {
	case string:
		return val
	case json.Number:
		return val.String()
	case fmt.Stringer:
		return val.String()
	default:
		return fmt.Sprintf("%v", v)
	}
}

func int64Value(v interface{}) int64 {
	switch val := v.(type) {
	case int64:
		return val
	case int:
		return int64(val)
	case float64:
		return int64(val)
	case json.Number:
		i, _ := val.Int64()
		return i
	case string:
		val = strings.TrimSpace(val)
		if val == "" {
			return 0
		}
		if i, err := strconv.ParseInt(val, 10, 64); err == nil {
			return i
		}
	}
	return 0
}

func bigIntValue(v interface{}) *big.Int {
	switch val := v.(type) {
	case string:
		n := new(big.Int)
		if _, ok := n.SetString(strings.TrimSpace(val), 10); ok {
			return n
		}
	case json.Number:
		n := new(big.Int)
		if _, ok := n.SetString(val.String(), 10); ok {
			return n
		}
	case float64:
		return big.NewInt(int64(val))
	case int64:
		return big.NewInt(val)
	case int:
		return big.NewInt(int64(val))
	}
	return nil
}

func formatAmountFromInt64(raw int64, decimals int) string {
	return formatAmountFromBigInt(big.NewInt(raw), decimals)
}

func formatAmountFromBigInt(raw *big.Int, decimals int) string {
	if raw == nil || raw.Sign() <= 0 {
		return "0"
	}
	if decimals <= 0 {
		return raw.String()
	}

	divisor := new(big.Int).Exp(big.NewInt(10), big.NewInt(int64(decimals)), nil)
	whole := new(big.Int)
	frac := new(big.Int)
	whole.Quo(raw, divisor)
	frac.Mod(raw, divisor)
	if frac.Sign() == 0 {
		return whole.String()
	}

	fracStr := frac.String()
	if len(fracStr) < decimals {
		fracStr = strings.Repeat("0", decimals-len(fracStr)) + fracStr
	}
	fracStr = strings.TrimRight(fracStr, "0")
	return whole.String() + "." + fracStr
}

func suiOwnerAddress(v interface{}) string {
	switch owner := v.(type) {
	case string:
		return owner
	case map[string]interface{}:
		for _, key := range []string{"AddressOwner", "ObjectOwner"} {
			if addr := strings.TrimSpace(stringValue(owner[key])); addr != "" {
				return addr
			}
		}
	}
	return ""
}

func suiSymbolFromCoinType(coinType string) string {
	if coinType == "0x2::sui::SUI" {
		return "SUI"
	}
	parts := strings.Split(coinType, "::")
	if len(parts) > 2 && parts[2] != "" {
		return parts[2]
	}
	return "SUI-Coin"
}
