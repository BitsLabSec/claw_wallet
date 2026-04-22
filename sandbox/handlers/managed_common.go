package handlers

import (
	"bytes"
	"context"
	"crypto/ecdh"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log"
	"math/big"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"reflect"
	"sandbox/internals/assets"
	"sandbox/internals/audit"
	gc "sandbox/internals/crypto"
	"sandbox/internals/oracle"
	"sandbox/internals/policy"
	"sandbox/internals/security"
	"sandbox/internals/signer"
	"sandbox/internals/utils"
	"strconv"
	"strings"
	"sync"
	"time"

	"golang.org/x/crypto/hkdf"
)

var (
	activeSigner         *signer.Signer
	sandboxServer        *http.Server
	policyEngine         *policy.Engine
	ephemeralPriv        *ecdh.PrivateKey
	pinExpiry            time.Time
	lockedReason         string
	mu                   = &sync.RWMutex{}
	activated            bool
	relayURL             string
	encShare1            signer.EncryptedShare
	encShare3            signer.EncryptedShare
	masterPubKey         string
	addresses            map[string]string
	boundUid             string // Persistent assigned UID attached to identity
	sekKey               []byte // Share Encryption Key (in memory, never written to disk in plaintext)
	remoteManagedWallet  bool
	localShare2          signer.EncryptedShare
	relayPINCache        = map[string]string{}
	buildVersion         = "dev"
	upgradeScriptBaseURL string

	// If POST /agent/unlock/complete fails after local activate, we must retry while activated=true
	// (otherwise provisionedUnlockLoop exits early and never notifies relay).
	pendingAgentUnlockCompleteUID string
	pendingAgentUnlockCompleteMu  sync.Mutex
)

const tronPublicSupportEnabled = false

func isPublicChainEnabled(chain string) bool {
	switch strings.ToLower(strings.TrimSpace(chain)) {
	case "tron":
		return tronPublicSupportEnabled
	default:
		return true
	}
}

func publicChainDisabledMessage(chain string) string {
	chain = strings.ToLower(strings.TrimSpace(chain))
	if chain == "" {
		return "chain support is disabled by default"
	}
	return fmt.Sprintf("%s support is disabled by default", chain)
}

func publicTrackedAddresses(input map[string]string) map[string]string {
	normalized := normalizedWalletAddresses(input)
	if len(normalized) == 0 {
		return map[string]string{}
	}
	out := make(map[string]string, len(normalized))
	for chain, address := range normalized {
		if !isPublicChainEnabled(chain) {
			continue
		}
		out[chain] = address
	}
	return out
}

func filterPublicRefreshState(input map[string]assets.RefreshState) map[string]assets.RefreshState {
	if len(input) == 0 {
		return input
	}
	out := make(map[string]assets.RefreshState, len(input))
	for key, state := range input {
		if !isPublicChainEnabled(state.Chain) {
			continue
		}
		out[key] = state
	}
	return out
}

func filterPublicCacheState(input map[string]assets.CacheStateView) map[string]assets.CacheStateView {
	if len(input) == 0 {
		return input
	}
	out := make(map[string]assets.CacheStateView, len(input))
	for key, state := range input {
		if !isPublicChainEnabled(state.Chain) {
			continue
		}
		out[key] = state
	}
	return out
}

func publicAssetSnapshot() map[string]any {
	snapshot := assets.Snapshot()
	out := make(map[string]any, len(snapshot))
	for key, entry := range snapshot {
		chain := key
		if idx := strings.Index(chain, ":"); idx >= 0 {
			chain = chain[:idx]
		}
		if !isPublicChainEnabled(chain) {
			continue
		}
		out[key] = entry
	}
	return out
}

func filterPublicHistoryRows(history []assets.Transaction) []assets.Transaction {
	if len(history) == 0 {
		return history
	}
	out := make([]assets.Transaction, 0, len(history))
	for _, item := range history {
		if !isPublicChainEnabled(item.Chain) {
			continue
		}
		out = append(out, item)
	}
	return out
}

// chainRPCEndpoints provides legacy single-endpoint fallbacks for chains that
// are not part of the multi-endpoint asset RPC pool.
var chainRPCEndpoints = map[string]string{
	// EVM Mainnet & L2s
	"ethereum":  "https://ethereum-rpc.publicnode.com",
	"0g":        "https://rpc.ankr.com/0g_mainnet_evm",
	"base":      "https://mainnet.base.org",
	"optimism":  "https://mainnet.optimism.io",
	"arbitrum":  "https://arb1.arbitrum.io/rpc",
	"polygon":   "https://polygon-bor-rpc.publicnode.com",
	"bsc":       "https://bsc.drpc.org",
	"avalanche": "https://api.avax.network/ext/bc/C/rpc",
	"zksync":    "https://mainnet.era.zksync.io",
	"linea":     "https://rpc.linea.build",
	"monad":     "https://rpc.monad.xyz",
	"tempo":     "https://rpc.moderato.tempo.xyz",
	"kite":      "https://rpc.gokite.ai/",
	"tron":      "https://api.trongrid.io",
	// Non-EVM
	"solana": "https://api.mainnet-beta.solana.com", // CORS-blocked in browser; MUST go through this proxy
	"sui":    "https://fullnode.mainnet.sui.io",

	"sepolia":    "https://sepolia.drpc.org",
	"solana_dev": "https://api.devnet.solana.com",
	"sui_test":   "https://fullnode.testnet.sui.io",
}

type jsonRPCMethodEnvelope struct {
	Method string `json:"method"`
}

func rpcProxyUpstreamURLs(chain string) []string {
	urls := assets.RPCProxyURLs(chain)
	if len(urls) > 0 {
		return urls
	}
	if url, ok := chainRPCEndpoints[chain]; ok && strings.TrimSpace(url) != "" {
		return []string{url}
	}
	return nil
}

func rpcMethodAllowsFallback(method string) bool {
	method = strings.ToLower(strings.TrimSpace(method))
	if method == "" {
		return false
	}
	switch method {
	case "eth_sendrawtransaction":
		return true
	}
	switch {
	case strings.HasPrefix(method, "eth_send"),
		strings.HasPrefix(method, "eth_sign"),
		strings.HasPrefix(method, "personal_"),
		strings.HasPrefix(method, "wallet_"),
		strings.HasPrefix(method, "debug_"),
		strings.HasPrefix(method, "trace_"),
		strings.HasPrefix(method, "admin_"),
		strings.HasPrefix(method, "miner_"),
		strings.HasPrefix(method, "engine_"):
		return false
	default:
		return true
	}
}

func rpcRequestAllowsFallback(body []byte) bool {
	trimmed := bytes.TrimSpace(body)
	if len(trimmed) == 0 {
		return false
	}
	if trimmed[0] == '[' {
		var batch []jsonRPCMethodEnvelope
		if err := json.Unmarshal(trimmed, &batch); err != nil || len(batch) == 0 {
			return false
		}
		for _, item := range batch {
			if !rpcMethodAllowsFallback(item.Method) {
				return false
			}
		}
		return true
	}
	var req jsonRPCMethodEnvelope
	if err := json.Unmarshal(trimmed, &req); err != nil {
		return false
	}
	return rpcMethodAllowsFallback(req.Method)
}

type jsonRPCErrorEnvelope struct {
	Error *struct {
		Code    int    `json:"code"`
		Message string `json:"message"`
	} `json:"error"`
}

func jsonRPCErrorIsRetryable(code int, message string) bool {
	msg := strings.ToLower(strings.TrimSpace(message))
	if code == -32005 || code == -32090 || code == 429 {
		return true
	}
	return strings.Contains(msg, "too many requests") ||
		strings.Contains(msg, "rate limit") ||
		strings.Contains(msg, "temporarily unavailable") ||
		strings.Contains(msg, "timeout") ||
		strings.Contains(msg, "try again")
}

func rpcResponseRequestsFallback(body []byte) bool {
	trimmed := bytes.TrimSpace(body)
	if len(trimmed) == 0 {
		return false
	}
	check := func(item jsonRPCErrorEnvelope) bool {
		return item.Error != nil && jsonRPCErrorIsRetryable(item.Error.Code, item.Error.Message)
	}
	if trimmed[0] == '[' {
		var batch []jsonRPCErrorEnvelope
		if err := json.Unmarshal(trimmed, &batch); err != nil {
			return false
		}
		for _, item := range batch {
			if check(item) {
				return true
			}
		}
		return false
	}
	var single jsonRPCErrorEnvelope
	if err := json.Unmarshal(trimmed, &single); err != nil {
		return false
	}
	return check(single)
}

func doRPCProxyRequest(urls []string, body []byte, allowFallback bool) (*http.Response, string, error) {
	if len(urls) == 0 {
		return nil, "", errors.New("no upstream RPC endpoints configured")
	}
	maxAttempts := 1
	timeout := 10 * time.Second
	if allowFallback {
		maxAttempts = len(urls)
		if maxAttempts > 4 {
			maxAttempts = 4
		}
		timeout = 3 * time.Second
	}

	var lastErr error
	lastURL := ""
	for i := 0; i < maxAttempts; i++ {
		lastURL = strings.TrimSpace(urls[i])
		if lastURL == "" {
			continue
		}
		req, err := http.NewRequest(http.MethodPost, lastURL, bytes.NewReader(body))
		if err != nil {
			lastErr = err
			continue
		}
		req.Header.Set("Content-Type", "application/json")

		client := &http.Client{Timeout: timeout}
		resp, err := client.Do(req)
		if err != nil {
			lastErr = err
			continue
		}
		if allowFallback && (resp.StatusCode < http.StatusOK || resp.StatusCode >= http.StatusMultipleChoices) {
			lastErr = fmt.Errorf("upstream returned HTTP %d", resp.StatusCode)
			resp.Body.Close()
			continue
		}
		if allowFallback {
			respBody, readErr := io.ReadAll(resp.Body)
			resp.Body.Close()
			if readErr != nil {
				lastErr = readErr
				continue
			}
			if rpcResponseRequestsFallback(respBody) {
				lastErr = errors.New("upstream returned retryable JSON-RPC error")
				continue
			}
			resp.Body = io.NopCloser(bytes.NewReader(respBody))
		}
		return resp, lastURL, nil
	}
	if lastErr == nil {
		lastErr = errors.New("all upstream RPC endpoints failed")
	}
	return nil, lastURL, lastErr
}

const (
	FactUsageRefreshTTL        = 30 * time.Second
	FactUsageRefreshMax        = 30 * time.Second
	RuntimeSandboxLabel        = "sandbox"
	assetRefreshTimeoutMessage = "asset refresh timed out; retry later"
)

type sandboxRuntimeMetrics struct {
	Status              string
	TTLRemainingSeconds *int64
	TTLUnlimited        bool
	TodayTxCount        int
	TodaySpentUSD       float64
}

var (
	assetRefreshMu        sync.Mutex
	assetRefreshDone      chan struct{}
	assetRefreshStartedAt time.Time
	assetRefreshFunc      = func(snapshot map[string]string) {
		for chain, address := range snapshot {
			assets.RefreshUsageFactsForChain(chain, address)
		}
	}
	assetRefreshBudget = FactUsageRefreshMax

	fullAssetRefreshMu        sync.Mutex
	fullAssetRefreshDone      chan struct{}
	fullAssetRefreshStartedAt time.Time
	fullAssetRefreshFunc      = assets.RefreshAll
	fullAssetRefreshBudget    = FactUsageRefreshMax
	assetAutoRefreshOnce      sync.Once
	startupAssetRefreshOnce   sync.Once
	asyncRefreshOneForPolicy  = func(chain, address string) {
		go assets.RefreshOne(chain, address)
	}
	asyncRefreshUsageFactsForPolicy = func(chain, address string) {
		go assets.RefreshUsageFactsForChain(chain, address)
	}
)

func normalizedWalletAddresses(input map[string]string) map[string]string {
	if len(input) == 0 {
		return map[string]string{}
	}
	out := make(map[string]string, len(input)+1)
	for chain, address := range input {
		key := strings.ToLower(strings.TrimSpace(chain))
		value := strings.TrimSpace(address)
		if key == "" || value == "" {
			continue
		}
		out[key] = value
	}
	if out["ethereum"] == "" && out["monad"] != "" {
		out["ethereum"] = out["monad"]
	}
	if out["monad"] == "" && out["ethereum"] != "" {
		out["monad"] = out["ethereum"]
	}
	if out["kite"] == "" && out["ethereum"] != "" {
		out["kite"] = out["ethereum"]
	}
	if out["tempo"] == "" && out["ethereum"] != "" {
		out["tempo"] = out["ethereum"]
	}
	return out
}

func startAssetAutoRefreshLoop() {
	assetAutoRefreshOnce.Do(func() {
		oracle.StartAutoRefresh()
		assets.StartAutoRefresh(func() map[string]string {
			mu.RLock()
			defer mu.RUnlock()

			return publicTrackedAddresses(addresses)
		})
	})
}

func TriggerStartupAssetRefresh() {
	startupAssetRefreshOnce.Do(func() {
		startAssetAutoRefreshLoop()
		go assets.RefreshAllRequested(publicTrackedAddresses(SnapshotAddresses()))
	})
}

func refreshAssetCacheWithBudget(snapshot map[string]string, reason string) bool {
	return refreshCacheWithBudget(
		snapshot,
		reason,
		"asset refresh",
		fullAssetRefreshBudget,
		&fullAssetRefreshMu,
		&fullAssetRefreshDone,
		&fullAssetRefreshStartedAt,
		fullAssetRefreshFunc,
	)
}

func refreshUsageFactsWithBudget(snapshot map[string]string, reason string) bool {
	return refreshCacheWithBudget(
		snapshot,
		reason,
		"usage refresh",
		assetRefreshBudget,
		&assetRefreshMu,
		&assetRefreshDone,
		&assetRefreshStartedAt,
		assetRefreshFunc,
	)
}

func refreshCacheWithBudget(
	snapshot map[string]string,
	reason string,
	label string,
	budget time.Duration,
	mu *sync.Mutex,
	doneRef *chan struct{},
	startedAtRef *time.Time,
	refreshFn func(map[string]string),
) bool {
	if len(snapshot) == 0 {
		return true
	}

	done, startedAt := acquireRefresh(snapshot, mu, doneRef, startedAtRef, refreshFn)
	waitStartedAt := time.Now()
	timer := time.NewTimer(budget)
	defer timer.Stop()

	select {
	case <-done:
		log.Printf("[claw wallet sandbox] %s completed in %s (waited=%s %s)", label, time.Since(startedAt).Round(time.Millisecond), time.Since(waitStartedAt).Round(time.Millisecond), reason)
		return true
	case <-timer.C:
		log.Printf("[claw wallet sandbox] %s exceeded %s after waiting %s (inflight=%s %s); continuing with cached snapshot", label, budget, time.Since(waitStartedAt).Round(time.Millisecond), time.Since(startedAt).Round(time.Millisecond), reason)
		return false
	}
}

func buildUsageRefreshSnapshot(chain string, snapshot map[string]string) map[string]string {
	chain = strings.ToLower(strings.TrimSpace(chain))
	if chain == "" || len(snapshot) == 0 {
		return nil
	}

	address := strings.TrimSpace(snapshot[chain])
	if address == "" && signer.IsEVMChain(chain) {
		address = strings.TrimSpace(snapshot["ethereum"])
	}
	if address == "" {
		return nil
	}
	return map[string]string{chain: address}
}

func ensureFreshUsageFacts(chain string, snapshot map[string]string, reason string) error {
	refreshSnapshot := buildUsageRefreshSnapshot(chain, snapshot)
	if len(refreshSnapshot) == 0 {
		log.Printf("[claw wallet sandbox] usage refresh skipped: no address for chain=%s (%s)", strings.ToLower(strings.TrimSpace(chain)), reason)
		return nil
	}

	var (
		resolvedChain   string
		resolvedAddress string
	)
	for k, v := range refreshSnapshot {
		resolvedChain = k
		resolvedAddress = v
	}

	if !assets.FullRefreshFreshForChain(resolvedChain, resolvedAddress, 60*time.Second) {
		log.Printf("[claw wallet sandbox] action refresh scheduled before %s: chain=%s", reason, resolvedChain)
		asyncRefreshOneForPolicy(resolvedChain, resolvedAddress)
	}

	if assets.HistoryFreshForChain(resolvedChain, resolvedAddress, FactUsageRefreshTTL) {
		log.Printf("[claw wallet sandbox] usage refresh skipped: current chain cache fresh chain=%s (%s)", resolvedChain, reason)
		return nil
	}

	log.Printf("[claw wallet sandbox] usage refresh deferred: continuing with cached snapshot chain=%s (%s)", resolvedChain, reason)
	asyncRefreshUsageFactsForPolicy(resolvedChain, resolvedAddress)
	return nil
}

func isAssetRefreshTimeout(err error) bool {
	return err != nil && err.Error() == assetRefreshTimeoutMessage
}

func acquireRefresh(
	snapshot map[string]string,
	mu *sync.Mutex,
	doneRef *chan struct{},
	startedAtRef *time.Time,
	refreshFn func(map[string]string),
) (<-chan struct{}, time.Time) {
	mu.Lock()
	defer mu.Unlock()

	if *doneRef != nil {
		return *doneRef, *startedAtRef
	}

	done := make(chan struct{})
	startedAt := time.Now()
	snapshotCopy := make(map[string]string, len(snapshot))
	for k, v := range snapshot {
		snapshotCopy[k] = v
	}

	*doneRef = done
	*startedAtRef = startedAt

	go func(refreshSnapshot map[string]string, doneCh chan struct{}) {
		defer func() {
			mu.Lock()
			*doneRef = nil
			*startedAtRef = time.Time{}
			mu.Unlock()
			close(doneCh)
		}()
		refreshFn(refreshSnapshot)
	}(snapshotCopy, done)

	return done, startedAt
}

func ApplyRuntimeState(state RuntimeState) {
	if state.Mu != nil {
		mu = state.Mu
	}
	sandboxServer = state.SandboxServer
	policyEngine = state.PolicyEngine
	relayURL = state.RelayURL
	encShare1 = state.EncShare1
	encShare3 = state.EncShare3
	masterPubKey = state.MasterPubKey
	addresses = normalizedWalletAddresses(state.Addresses)
	boundUid = state.BoundUid
	if state.SekKey != nil {
		sekKey = append([]byte(nil), state.SekKey...)
	}
	remoteManagedWallet = state.RemoteManaged
	if strings.TrimSpace(state.BuildVersion) != "" {
		buildVersion = strings.TrimSpace(state.BuildVersion)
	}
	if strings.TrimSpace(state.UpgradeScriptBaseURL) != "" {
		upgradeScriptBaseURL = strings.TrimSpace(state.UpgradeScriptBaseURL)
	}
	startAssetAutoRefreshLoop()
}

func (e *Share2GateError) Error() string {
	return e.reason
}

func loadSEKFromIdentityFile(identityPath string) ([]byte, error) {
	return LoadSEKFromIdentityOrWrappedFile(identityPath)
}

func handleWalletRefresh(w http.ResponseWriter, r *http.Request) {
	mu.RLock()
	defer mu.RUnlock()
	startAssetAutoRefreshLoop()
	go assets.RefreshAllRequested(publicTrackedAddresses(addresses))
	w.Write([]byte(`{"status": "refresh_triggered"}`))
}

func handleWalletRefreshChain(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}

	var req struct {
		Chain string `json:"chain"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil && err != io.EOF {
		http.Error(w, "bad request", http.StatusBadRequest)
		return
	}
	req.Chain = strings.ToLower(strings.TrimSpace(req.Chain))
	if req.Chain == "" {
		http.Error(w, "chain is required", http.StatusBadRequest)
		return
	}
	if !isPublicChainEnabled(req.Chain) {
		http.Error(w, publicChainDisabledMessage(req.Chain), http.StatusBadRequest)
		return
	}

	mu.RLock()
	snapshot := publicTrackedAddresses(addresses)
	mu.RUnlock()

	address, err := utils.TransferFromAddress(req.Chain, snapshot)
	if err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}

	startAssetAutoRefreshLoop()
	requestStartedAt := time.Now()
	if waitStartedAt, done := assets.WaitForSlowChainRefresh(req.Chain, address); done != nil {
		select {
		case <-done:
		case <-r.Context().Done():
			http.Error(w, "request canceled", http.StatusRequestTimeout)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(map[string]any{
			"status":        "refresh_waited_existing",
			"chain":         req.Chain,
			"address":       address,
			"started_at":    waitStartedAt.UTC().Format(time.RFC3339),
			"waited_ms":     time.Since(requestStartedAt).Milliseconds(),
			"refresh_state": assets.RefreshStateSnapshot(),
		})
		return
	}

	if assets.RecentRefreshAttempted(req.Chain, address, 15*time.Second) {
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(map[string]any{
			"status":        "refresh_skipped_recent",
			"chain":         req.Chain,
			"address":       address,
			"duration_ms":   time.Since(requestStartedAt).Milliseconds(),
			"refresh_state": assets.RefreshStateSnapshot(),
		})
		return
	}

	assets.RefreshOneForce(req.Chain, address)
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(map[string]any{
		"status":        "refresh_completed",
		"chain":         req.Chain,
		"address":       address,
		"duration_ms":   time.Since(requestStartedAt).Milliseconds(),
		"refresh_state": assets.RefreshStateSnapshot(),
	})
}

func handleShutdown(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	server := sandboxServer
	if server == nil {
		http.Error(w, "sandbox server unavailable", http.StatusInternalServerError)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]string{"status": "shutting_down"})

	go func() {
		time.Sleep(100 * time.Millisecond)
		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		server.Shutdown(ctx)
	}()
}

func handleStatus(w http.ResponseWriter, r *http.Request) {
	mu.Lock()
	if sessionExpiredLocked() {
		ExpireActiveSessionLocked("ttl_expired")
	}
	usage := policyEngine.UsageSnapshot()
	status := walletStatusLocked()
	ttlRemainingSeconds, ttlUnlimited := currentPINResidencyLocked()

	res := map[string]interface{}{
		"uid":                       boundUid,
		"sandbox_version":           buildVersion,
		"address":                   addresses["ethereum"],
		"addresses":                 publicTrackedAddresses(addresses),
		"address_explorers":         addressExplorersLocked(),
		"master_pub_key":            masterPubKey,
		"status":                    status,
		"gateway_status":            gatewayStatusLabel(status),
		"has_provisioned_share1":    hasRemoteManagedShareLocked(),
		"can_reactivate_locally":    canReactivateLocallyLocked(),
		"policy":                    policyEngine.Current(),
		"today_spent_wei":           policyEngine.TodaySpentWei(),
		"today_spent_usd":           policyEngine.TodaySpentUSD(),
		"today_tx_count":            policyEngine.TodayTxCount(),
		"today_local_spent_wei":     usage.LocalSpentWei,
		"today_local_spent_usd":     usage.LocalSpentUSD,
		"today_local_tx_count":      usage.LocalTxCount,
		"today_onchain_spent_usd":   usage.OnChainSpentUSD,
		"today_onchain_tx_count":    usage.OnChainTxCount,
		"today_effective_spent_usd": usage.EffectiveSpentUSD,
		"today_effective_tx_count":  usage.EffectiveTxCount,
		"ttl_unlimited":             ttlUnlimited,
	}
	if ttlRemainingSeconds != nil {
		res["ttl_remaining_seconds"] = *ttlRemainingSeconds
	}
	if reason := walletLockedReasonLocked(); reason != "" {
		res["locked_reason"] = reason
	}
	if activated && !pinExpiry.IsZero() {
		res["pin_residency_expires_at"] = pinExpiry.UTC().Format(time.RFC3339)
	}
	mu.Unlock()

	oracleStatus := oracle.Status()
	res["oracle_healthy"] = oracleStatus.Healthy
	res["oracle_native"] = oracleStatus.Healthy
	res["oracle_tokens"] = true
	res["oracle_forced_unavailable"] = oracleStatus.ForcedUnavailable
	res["oracle_native_stale_seconds"] = int64(oracleStatus.NativeStaleFor / time.Second)
	if !oracleStatus.LastRefreshAttempt.IsZero() {
		res["oracle_last_refresh_attempt_at"] = oracleStatus.LastRefreshAttempt.UTC().Format(time.RFC3339)
	}
	if !oracleStatus.LastRefreshSuccess.IsZero() {
		res["oracle_last_refresh_success_at"] = oracleStatus.LastRefreshSuccess.UTC().Format(time.RFC3339)
	}
	if oracleStatus.LastRefreshError != "" {
		res["oracle_last_refresh_error"] = oracleStatus.LastRefreshError
	}
	if !oracleStatus.Healthy {
		oracle.MaybeRefreshAsync("wallet_status")
	}

	res["local_paths"] = map[string]string{
		"identity_path": absPathOrValue(env("IDENTITY_PATH", "identity.json")),
		"share1_path":   absPathOrValue(env("SHARE1_PATH", "share1.json")),
		"share3_path":   absPathOrValue(env("SHARE3_PATH", "share3.json")),
		"policy_path":   absPathOrValue(env("POLICY_PATH", "policy.json")),
	}
	if uid := strings.TrimSpace(boundUid); uid != "" {
		relayBindingStatus, relayUserBound := fetchRelayWalletBindingStatus(uid)
		res["relay_binding_status"] = relayBindingStatus
		res["relay_user_bound"] = relayUserBound
	}
	res["asset_refresh_state"] = filterPublicRefreshState(assets.RefreshStateSnapshot())
	res["asset_auto_refresh_interval_seconds"] = assets.AutoRefreshIntervalSeconds()
	res["asset_cache_state"] = filterPublicCacheState(assets.CacheStateSnapshot())

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(res)
}

func handleBackupExport(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}

	identityPath := env("IDENTITY_PATH", "identity.json")
	share1Path := env("SHARE1_PATH", "share1.json")
	share3Path := env("SHARE3_PATH", "share3.json")
	policyPath := env("POLICY_PATH", "policy.json")

	identityPayload, err := readOptionalJSONFile(identityPath)
	if err != nil {
		http.Error(w, "failed to read identity backup: "+err.Error(), http.StatusInternalServerError)
		return
	}
	share1Payload, err := readOptionalJSONFile(share1Path)
	if err != nil {
		http.Error(w, "failed to read share1 backup: "+err.Error(), http.StatusInternalServerError)
		return
	}
	share3Payload, err := readOptionalJSONFile(share3Path)
	if err != nil {
		http.Error(w, "failed to read share3 backup: "+err.Error(), http.StatusInternalServerError)
		return
	}
	policyPayload, err := readOptionalJSONFile(policyPath)
	if err != nil {
		http.Error(w, "failed to read policy backup: "+err.Error(), http.StatusInternalServerError)
		return
	}

	mu.RLock()
	res := map[string]interface{}{
		"uid":            boundUid,
		"master_pub_key": masterPubKey,
		"addresses":      addresses,
		"gateway_status": gatewayStatusLabel(walletStatusLocked()),
		"agent_token":    env("AGENT_TOKEN", ""),
		"identity":       identityPayload,
		"share1":         share1Payload,
		"share3":         share3Payload,
		"policy":         policyPayload,
		"local_paths": map[string]string{
			"identity_path": absPathOrValue(identityPath),
			"share1_path":   absPathOrValue(share1Path),
			"share3_path":   absPathOrValue(share3Path),
			"policy_path":   absPathOrValue(policyPath),
		},
		"exported_at": time.Now().UTC().Format(time.RFC3339),
	}
	if uid := strings.TrimSpace(boundUid); uid != "" {
		relayBindingStatus, relayUserBound := fetchRelayWalletBindingStatus(uid)
		res["relay_binding_status"] = relayBindingStatus
		res["relay_user_bound"] = relayUserBound
	}
	mu.RUnlock()

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(res)
}

func handleWalletUnlock(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}

	var req struct {
		PIN string `json:"pin"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, "bad request", http.StatusBadRequest)
		return
	}
	req.PIN = strings.TrimSpace(req.PIN)
	if req.PIN == "" {
		http.Error(w, "pin is required", http.StatusBadRequest)
		return
	}

	uid, priv := ensureControlPlaneSession()
	if err := syncPendingPolicyBeforeProvisionedUnlock(uid, priv); err != nil {
		http.Error(w, "failed to sync latest wallet policy before unlock: "+err.Error(), http.StatusServiceUnavailable)
		return
	}

	mu.Lock()
	defer mu.Unlock()

	if !hasRemoteManagedShareLocked() {
		http.Error(w, "wallet unlock is only available for imported phase2 provisioned wallets", http.StatusConflict)
		return
	}
	if err := activateProvisionedWithPrivLocked(req.PIN, priv); err != nil {
		http.Error(w, err.Error(), http.StatusUnauthorized)
		return
	}
	respondWalletStateLocked(w)
}

func HandleReactivate(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}

	mu.RLock()
	isActive := activated
	uid := strings.TrimSpace(boundUid)
	currentPriv := ephemeralPriv
	master := masterPubKey
	hasRemoteManagedShare := hasRemoteManagedShareLocked()
	hasLegacyLocalShare := hasLegacyLocalShareLocked()
	isRemoteManaged := remoteManagedWallet
	sekAvailable := len(sekKey) > 0
	sekPIN := ""
	if sekAvailable {
		sekCopy := append([]byte(nil), sekKey...)
		sekPIN = hex.EncodeToString(sekCopy)
	}
	mu.RUnlock()

	if isActive {
		refreshSandboxHeartbeat(uid, currentPriv)
		mu.Lock()
		respondWalletStateLocked(w)
		mu.Unlock()
		return
	}
	if master == "" {
		http.Error(w, "wallet identity not initialized", http.StatusBadRequest)
		return
	}
	if isRemoteManaged || hasRemoteManagedShare {
		http.Error(w, "reactivate is only available for locally initialized wallets; imported wallets must use /api/v1/wallet/unlock", http.StatusConflict)
		return
	}
	if !hasLegacyLocalShare {
		http.Error(w, "encrypted share3 is unavailable", http.StatusConflict)
		return
	}
	if !sekAvailable {
		http.Error(w, "local SEK unavailable; restart or reinstall the sandbox to recover local activation", http.StatusConflict)
		return
	}
	mu.Lock()
	if err := activateWithSharePINLocked(sekPIN); err != nil {
		lockedReason = "reactivation_failed"
		mu.Unlock()
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	respondWalletStateLocked(w)
	mu.Unlock()
}

// handlePriceCache returns the current oracle price snapshot and health status
func handlePriceCache(w http.ResponseWriter, r *http.Request) {
	if err := oracle.EnsureFresh(); err != nil {
		log.Printf("[claw wallet sandbox] oracle ensure fresh failed for price cache: %v", err)
	}
	status := oracle.Status()

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]interface{}{
		"prices":                      oracle.Snapshot(),
		"oracle_healthy":              status.Healthy,
		"oracle_forced_unavailable":   status.ForcedUnavailable,
		"oracle_native_stale_seconds": int64(status.NativeStaleFor / time.Second),
		"oracle_last_refresh_error":   status.LastRefreshError,
		"oracle_last_refresh_attempt_at": func() string {
			if status.LastRefreshAttempt.IsZero() {
				return ""
			}
			return status.LastRefreshAttempt.UTC().Format(time.RFC3339)
		}(),
		"oracle_last_refresh_success_at": func() string {
			if status.LastRefreshSuccess.IsZero() {
				return ""
			}
			return status.LastRefreshSuccess.UTC().Format(time.RFC3339)
		}(),
	})
}

type oracleTestStateRequest struct {
	ForcedUnavailable *bool              `json:"forced_unavailable"`
	Snapshot          map[string]float64 `json:"snapshot"`
}

func handleOracleTestState(w http.ResponseWriter, r *http.Request) {
	if buildVersion != "dev" && env("CLAY_ENABLE_TEST_ENDPOINTS", "") != "1" {
		http.NotFound(w, r)
		return
	}

	switch r.Method {
	case http.MethodGet:
	case http.MethodPost:
		var req oracleTestStateRequest
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil && err != io.EOF {
			http.Error(w, "invalid oracle test payload", http.StatusBadRequest)
			return
		}
		if req.Snapshot != nil {
			oracle.RestoreForTest(req.Snapshot)
		}
		if req.ForcedUnavailable != nil {
			oracle.SetForcedUnavailableForTest(*req.ForcedUnavailable)
		}
	default:
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]interface{}{
		"oracle_healthy":     oracle.IsHealthy(),
		"forced_unavailable": oracle.ForcedUnavailableForTest(),
		"prices":             oracle.Snapshot(),
	})
}

func handleSecurityCache(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]interface{}{
		"security": security.Snapshot(),
	})
}

// 刷新资产 并且返回最新的资产快照（主要是为了在前端操作后能够立刻看到变化，避免等下一次自动刷新）
func handleWalletRefreshAndAssets(w http.ResponseWriter, r *http.Request) {
	startAssetAutoRefreshLoop()
	assets.RefreshAllRequested(publicTrackedAddresses(SnapshotAddresses()))
	// 返回最新的资产快照
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(publicAssetSnapshot())
}

// handleAssets returns the current multichain assets snapshot, refreshing only when stale.
func handleAssets(w http.ResponseWriter, r *http.Request) {
	startAssetAutoRefreshLoop()
	// 刷新资产
	refreshAssetCacheWithBudget(publicTrackedAddresses(SnapshotAddresses()), "wallet_assets")
	// 返回最新的资产快照
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(publicAssetSnapshot())
}

func handleAuditLogs(w http.ResponseWriter, r *http.Request) {
	limit := 50
	if raw := strings.TrimSpace(r.URL.Query().Get("limit")); raw != "" {
		if n, err := strconv.Atoi(raw); err == nil && n > 0 {
			limit = n
		}
	}
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(audit.GetLogs(limit))
}

func handleWalletHistory(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	chain := strings.ToLower(strings.TrimSpace(r.URL.Query().Get("chain")))
	if chain != "" && chain != "all" && !isPublicChainEnabled(chain) {
		http.Error(w, publicChainDisabledMessage(chain), http.StatusBadRequest)
		return
	}
	limit := 0
	if raw := strings.TrimSpace(r.URL.Query().Get("limit")); raw != "" {
		if n, err := strconv.Atoi(raw); err == nil && n > 0 {
			limit = n
		}
	}
	var history []assets.Transaction
	if chain != "" && chain != "all" {
		history = assets.HistorySnapshotByChain(chain)
	} else {
		history = assets.HistorySnapshot()
	}
	history = filterPublicHistoryRows(history)
	if limit > 0 && len(history) > limit {
		history = history[:limit]
	}
	json.NewEncoder(w).Encode(history)
}

// handleLocalPolicyConfig serves the decrypted local policy JSON (GET only).
func handleLocalPolicyConfig(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}

	policyPath := env("POLICY_PATH", "policy.json")
	payload, err := policy.ReadStoredPolicyBytes(policyPath)
	if err != nil {
		if os.IsNotExist(err) {
			http.Error(w, "policy file not found", http.StatusNotFound)
			return
		}
		http.Error(w, "failed to read policy file", http.StatusInternalServerError)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	w.Write(payload)
}

func handleLocalPolicyUpdate(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost && r.Method != http.MethodPut {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	if policyEngine == nil {
		http.Error(w, "policy engine not initialized", http.StatusInternalServerError)
		return
	}

	var req localPolicyUpdateRequest
	dec := json.NewDecoder(r.Body)
	dec.DisallowUnknownFields()
	if err := dec.Decode(&req); err != nil {
		http.Error(w, "bad policy payload", http.StatusBadRequest)
		return
	}

	currentPolicy := policyEngine.Current()
	currentSyncPayload := buildLocalPolicySyncPayloadForPolicy(currentPolicy)
	currentSyncHash, err := hashLocalPolicySyncPayload(currentSyncPayload)
	if err != nil {
		http.Error(w, "failed to hash current policy", http.StatusInternalServerError)
		return
	}

	next, err := buildUpdatedLocalPolicy(currentPolicy, req)
	if err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}

	payload, err := json.MarshalIndent(next, "", "  ")
	if err != nil {
		http.Error(w, "failed to encode policy", http.StatusInternalServerError)
		return
	}
	if err := policy.WriteStoredPolicyBytes(env("POLICY_PATH", "policy.json"), payload); err != nil {
		http.Error(w, "failed to persist policy", http.StatusInternalServerError)
		return
	}
	if err := policyEngine.Reload(); err != nil {
		http.Error(w, "failed to reload policy", http.StatusInternalServerError)
		return
	}
	setLastLocalPolicyPrevHash(currentSyncHash)

	mu.Lock()
	if activated {
		reconcilePINResidencyLockedOnPolicyChange()
	}
	uid := strings.TrimSpace(boundUid)
	priv := ephemeralPriv
	shouldSyncLocalPolicy := activated && uid != "" && priv != nil
	mu.Unlock()

	if shouldSyncLocalPolicy {
		if err := postAgentSyncForUID(uid, priv); err != nil {
			log.Printf("[claw wallet sandbox] local policy sync failed uid=%s err=%v", uid, err)
			http.Error(w, "failed to sync local policy", http.StatusBadGateway)
			return
		}
	}

	var syncResult any
	if shouldSyncLocalPolicy {
		snap := agentSyncSnapshot()
		if len(snap.LocalPolicySync) > 0 && strings.TrimSpace(string(snap.LocalPolicySync)) != "" && strings.TrimSpace(string(snap.LocalPolicySync)) != "null" {
			var parsed map[string]any
			if err := json.Unmarshal(snap.LocalPolicySync, &parsed); err == nil {
				syncResult = parsed
			}
		}
	}

	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(map[string]any{
		"status":      "policy_updated",
		"policy":      policyEngine.Current(),
		"sync_result": syncResult,
	})
}

func buildUpdatedLocalPolicy(current policy.Policy, req localPolicyUpdateRequest) (policy.Policy, error) {
	next := current

	otherUpdates := req.MaxAmountPerTxUSD != nil || req.DailyLimitUSD != nil || req.DailyMaxTxCount != nil || req.BlacklistTo != nil || req.UnpricedAssetPolicy != nil || req.AllowBlindSign != nil || req.StrictPlainText != nil

	if req.MaxAmountPerTxUSD != nil {
		if *req.MaxAmountPerTxUSD < 0 || *req.MaxAmountPerTxUSD > 1000 {
			return policy.Policy{}, fmt.Errorf("max_amount_per_tx_usd must be between 0 and 1000")
		}
		next.MaxAmountPerTxUSD = *req.MaxAmountPerTxUSD
	}
	if req.DailyLimitUSD != nil {
		if *req.DailyLimitUSD < 0 || *req.DailyLimitUSD > 10000 {
			return policy.Policy{}, fmt.Errorf("daily_limit_usd must be between 0 and 10000")
		}
		next.DailyLimitUSD = *req.DailyLimitUSD
	}
	if req.DailyMaxTxCount != nil {
		if *req.DailyMaxTxCount < 0 || *req.DailyMaxTxCount > 10000 {
			return policy.Policy{}, fmt.Errorf("daily_max_tx_count must be between 0 and 10000")
		}
		next.DailyMaxTxCount = *req.DailyMaxTxCount
	}
	if req.WhitelistTo != nil {
		return policy.Policy{}, fmt.Errorf("whitelist_to is managed by backend policy sync")
	}
	if req.BlacklistTo != nil {
		if len(*req.BlacklistTo) == 0 && otherUpdates {
			next.BlacklistTo = []policy.AddressNote{}
		} else {
			blacklist, err := normalizeAddressNotes(*req.BlacklistTo, "blacklist_to")
			if err != nil {
				return policy.Policy{}, err
			}
			next.BlacklistTo = blacklist
		}
	}
	if req.UnpricedAssetPolicy != nil {
		value := strings.ToLower(strings.TrimSpace(*req.UnpricedAssetPolicy))
		if value != "allow" && value != "block" {
			return policy.Policy{}, fmt.Errorf("unpriced_asset_policy must be allow or block")
		}
		next.UnpricedAssetPolicy = value
	}
	if req.AllowBlindSign != nil {
		next.AllowBlindSign = *req.AllowBlindSign
	}
	if req.StrictPlainText != nil {
		next.StrictPlainText = *req.StrictPlainText
	}

	return next, nil
}

func normalizeAddressNotes(notes []policy.AddressNote, fieldName string) ([]policy.AddressNote, error) {
	out := make([]policy.AddressNote, 0, len(notes))
	for _, note := range notes {
		address := strings.TrimSpace(note.Address)
		if address == "" {
			return nil, fmt.Errorf("%s contains an empty address", fieldName)
		}
		out = append(out, policy.AddressNote{
			Address: address,
			Note:    strings.TrimSpace(note.Note),
			Chain:   strings.ToLower(strings.TrimSpace(note.Chain)),
		})
	}
	return out, nil
}

// 初始化身份和钱包地址等信息，供后续使用
func HandleInitialize(w http.ResponseWriter, r *http.Request) {
	mu.Lock()
	defer mu.Unlock()

	if masterPubKey != "" {
		http.Error(w, "Identity already set. Use /reset to clear signature and identity.", http.StatusForbidden)
		return
	}

	var body struct {
		MasterPubKey string            `json:"master_pub_key"`
		Addresses    map[string]string `json:"addresses"`
		UID          string            `json:"uid,omitempty"`
	}
	if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
		http.Error(w, "bad request", http.StatusBadRequest)
		return
	}

	masterPubKey = body.MasterPubKey
	if body.Addresses != nil {
		addresses = normalizedWalletAddresses(body.Addresses)
	}
	if body.UID != "" {
		boundUid = body.UID
	}
	persistedAddresses := normalizedWalletAddresses(addresses)
	assets.TouchWalletEntries(persistedAddresses)

	idData, _ := json.Marshal(map[string]any{
		"master_pub_key": body.MasterPubKey,
		"addresses":      persistedAddresses,
		"uid":            body.UID,
		"agent_token":    env("AGENT_TOKEN", ""),
	})
	if err := utils.AtomicWrite(env("IDENTITY_PATH", "identity.json"), idData); err != nil {
		log.Printf("[claw wallet sandbox] Warning: failed to persist identity: %v", err)
	}

	log.Printf("[claw wallet sandbox] Identity initialized: %s", masterPubKey)
	startAssetAutoRefreshLoop()
	w.Write([]byte(`{"status": "initialized"}`))
}

func handleBindUID(w http.ResponseWriter, r *http.Request) {
	mu.Lock()
	defer mu.Unlock()

	var req struct {
		UID string `json:"uid"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil || req.UID == "" {
		http.Error(w, "bad request", http.StatusBadRequest)
		return
	}

	boundUid = req.UID
	remoteManagedWallet = true

	// Re-construct identity for saving
	var id struct {
		MasterPubKey string            `json:"master_pub_key"`
		Addresses    map[string]string `json:"addresses"`
		UID          string            `json:"uid"`
		WrappedSEK   string            `json:"wrapped_sek,omitempty"`
		AgentToken   string            `json:"agent_token,omitempty"`
	}
	// Attempt to keep existing SEK wrapper
	identityPath := env("IDENTITY_PATH", "identity.json")
	if data, err := os.ReadFile(identityPath); err == nil {
		json.Unmarshal(data, &id)
	}
	id.MasterPubKey = masterPubKey
	id.Addresses = addresses
	id.UID = boundUid
	if strings.TrimSpace(id.AgentToken) == "" {
		id.AgentToken = env("AGENT_TOKEN", "")
	}

	wrappedSEK := strings.TrimSpace(id.WrappedSEK)
	agentToken := strings.TrimSpace(id.AgentToken)
	if wrappedSEK == "" {
		if record, err := loadWrappedSEKRecord(WrappedSEKPath(identityPath)); err == nil {
			wrappedSEK = strings.TrimSpace(record.WrappedSEK)
			if agentToken == "" {
				agentToken = strings.TrimSpace(record.AgentToken)
			}
		}
	}
	id.WrappedSEK = ""
	idData, _ := json.Marshal(id)
	if err := utils.AtomicWrite(identityPath, idData); err != nil {
		log.Printf("[claw wallet sandbox] Warning: failed to persist bound identity: %v", err)
	}
	if err := EnsureWrappedSEKFile(identityPath, wrappedSEK, agentToken); err != nil {
		log.Printf("[claw wallet sandbox] Warning: failed to persist wrapped_sek.json for bound wallet: %v", err)
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]string{"status": "success", "uid": boundUid})
}

func handleWalletBind(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}

	var req struct {
		MessageHashHex string `json:"message_hash_hex"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil || strings.TrimSpace(req.MessageHashHex) == "" {
		http.Error(w, "message_hash_hex is required", http.StatusBadRequest)
		return
	}
	msgHashHex := strings.TrimSpace(req.MessageHashHex)

	bindRespBody, err := submitWalletBindFromChallenge(msgHashHex)
	if err != nil {
		http.Error(w, err.Error(), http.StatusBadGateway)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	w.Write(bindRespBody)
}

func submitWalletBindFromChallenge(msgHashHex string) ([]byte, error) {
	mu.RLock()
	s := activeSigner
	uid := boundUid
	mu.RUnlock()

	if s == nil {
		return nil, fmt.Errorf("sandbox not activated; run 'reactivate' or unlock before binding")
	}
	if uid == "" {
		return nil, fmt.Errorf("wallet has no uid; initialize wallet first")
	}

	// Sign the 32-byte hash directly with the master key (btcec.PrivKeyFromBytes(seed)),
	// which matches masterPubKey stored in clay_shares on the relay.
	signReq := &signer.SignRequest{
		UID:             uid,
		Chain:           "master",
		SignMode:        "raw_hash",
		TxPayloadHex:    msgHashHex,
		ConfirmedByUser: true,
	}

	if err := PopulateSigningShares(signReq); err != nil {
		if gateErr, ok := err.(*Share2GateError); ok {
			return nil, fmt.Errorf("share2 gate rejected bind signing: %s", gateErr.reason)
		}
		return nil, fmt.Errorf("failed to acquire signing share: %w", err)
	}

	result, err := s.Sign(signReq)
	if err != nil {
		return nil, fmt.Errorf("signing failed: %w", err)
	}

	bindBody, _ := json.Marshal(map[string]interface{}{
		"message_hash_hex": msgHashHex,
		"signature_hex":    result.SignatureHex,
	})
	bindResp, err := (&http.Client{Timeout: 15 * time.Second}).Post(
		strings.TrimRight(relayURL, "/")+"/wallets/bind",
		"application/json",
		bytes.NewReader(bindBody),
	)
	if err != nil {
		return nil, fmt.Errorf("failed to submit bind to relay: %w", err)
	}
	defer bindResp.Body.Close()
	bindRespBody, _ := io.ReadAll(io.LimitReader(bindResp.Body, 4096))

	if bindResp.StatusCode != http.StatusOK {
		statusCode := http.StatusBadGateway
		if bindResp.StatusCode >= 400 && bindResp.StatusCode < 500 {
			statusCode = bindResp.StatusCode
		}
		return nil, fmt.Errorf("bind failed (%d): %s", statusCode, strings.TrimSpace(string(bindRespBody)))
	}

	return bindRespBody, nil
}

func handleWalletImport(w http.ResponseWriter, r *http.Request) {
	mu.Lock()
	defer mu.Unlock()

	var req struct {
		UID          string                `json:"uid"`
		MasterPubKey string                `json:"master_pub_key"`
		Addresses    map[string]string     `json:"addresses"`
		EncShare3    signer.EncryptedShare `json:"enc_share3"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, "bad request", http.StatusBadRequest)
		return
	}
	if err := importProvisionedWalletLocked(req.UID, req.MasterPubKey, req.Addresses, req.EncShare3); err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]any{
		"status":    walletStatusLocked(),
		"uid":       boundUid,
		"addresses": addresses,
	})
}

func handleWalletProvisionClaim(w http.ResponseWriter, r *http.Request) {
	mu.Lock()
	defer mu.Unlock()

	var req struct {
		UID string `json:"uid"`
		OTP string `json:"otp"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, "bad request", http.StatusBadRequest)
		return
	}
	if strings.TrimSpace(req.UID) == "" {
		http.Error(w, "uid is required", http.StatusBadRequest)
		return
	}
	if strings.TrimSpace(req.OTP) == "" {
		http.Error(w, "otp is required", http.StatusBadRequest)
		return
	}

	priv := ephemeralPriv
	if priv == nil {
		curve := ecdh.P256()
		var genErr error
		priv, genErr = curve.GenerateKey(rand.Reader)
		if genErr != nil {
			http.Error(w, "failed to create ephemeral claim key", http.StatusInternalServerError)
			return
		}
		ephemeralPriv = priv
	}
	if err := publishSandboxConnect(strings.TrimSpace(req.UID), priv); err != nil {
		http.Error(w, "failed to publish sandbox identity", http.StatusBadGateway)
		return
	}

	claimBody, _ := json.Marshal(map[string]string{
		"uid": req.UID,
		"otp": req.OTP,
	})
	resp, err := http.Post(strings.TrimRight(relayURL, "/")+"/agent/provision/claim", "application/json", bytes.NewReader(claimBody))
	if err != nil {
		http.Error(w, "failed to claim provisioned wallet", http.StatusBadGateway)
		return
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(io.LimitReader(resp.Body, 2048))
		statusCode := http.StatusBadGateway
		if resp.StatusCode >= 400 && resp.StatusCode < 500 {
			statusCode = resp.StatusCode
		}
		http.Error(w, fmt.Sprintf("claim failed: %s", strings.TrimSpace(string(body))), statusCode)
		return
	}

	var payload struct {
		UID          string                `json:"uid"`
		MasterPubKey string                `json:"master_pub_key"`
		Addresses    map[string]string     `json:"addresses"`
		EncShare3    signer.EncryptedShare `json:"enc_share3"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&payload); err != nil {
		http.Error(w, "invalid relay response", http.StatusBadGateway)
		return
	}
	if err := importProvisionedWalletLocked(payload.UID, payload.MasterPubKey, payload.Addresses, payload.EncShare3); err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]any{
		"status":    walletStatusLocked(),
		"uid":       boundUid,
		"addresses": addresses,
	})
}

func handleHardReset(w http.ResponseWriter, r *http.Request) {
	mu.Lock()
	defer mu.Unlock()

	if activeSigner != nil {
		activeSigner.Wipe()
		activeSigner = nil
	}
	activated = false
	lockedReason = ""
	masterPubKey = ""
	encShare1 = signer.EncryptedShare{}
	encShare3 = signer.EncryptedShare{}
	localShare2 = signer.EncryptedShare{}
	remoteManagedWallet = false
	os.Remove(env("IDENTITY_PATH", "identity.json"))
	os.Remove(env("SHARE1_PATH", "share1.json"))
	os.Remove(env("SHARE3_PATH", "share3.json"))
	log.Println("[claw wallet sandbox] Hard reset: identity and memory cleared")
	w.Write([]byte(`{"status": "hard_reset_complete"}`))
}

func handleCreate(w http.ResponseWriter, r *http.Request) {
	mu.Lock()
	defer mu.Unlock()

	var body struct {
		MasterPIN string `json:"master_pin"`
	}
	_ = json.NewDecoder(r.Body).Decode(&body)

	if masterPubKey != "" && len(addresses) > 0 {
		if !activated && len(sekKey) > 0 {
			if err := activateWithSharePINLocked(hex.EncodeToString(sekKey)); err != nil {
				log.Printf("[claw wallet sandbox] Existing wallet re-activation via init failed: %v", err)
			}
		}
		payload := walletInitResponsePayload(boundUid, walletStatusLocked(), addresses, true, walletLockedReasonLocked())
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(payload)
		return
	}

	// 1.12: Generate an independent Share Encryption Key (SEK) for this wallet.
	// SEK is separate from AGENT_TOKEN. On restart, SEK is unwrapped from identity.json using KEK.
	// KEK = HKDF(AGENT_TOKEN + machine-fingerprint) 闁?so even if OpenClaw knows the token, it
	// cannot unwrap SEK without running on the same machine under the same binary path.
	newSEK, err := gc.GenerateSEK()
	if err != nil {
		http.Error(w, "failed to generate share encryption key", 500)
		return
	}
	kek := gc.DeriveKEK(env("AGENT_TOKEN", ""), env("IDENTITY_PATH", "identity.json"))
	wrappedSEK, err := gc.WrapSEK(newSEK, kek)
	if err != nil {
		http.Error(w, "failed to wrap share encryption key", 500)
		return
	}

	// Use hex-encoded SEK as the share PIN (internal, not user-facing)
	shareEncPIN := hex.EncodeToString(newSEK)

	if body.MasterPIN == "" {
		// Provide the SEK as the PIN so shares are encrypted with it
		body.MasterPIN = shareEncPIN
	}

	// 1. Generate new keys via Signer using the SEK as PIN
	tempSigner := &signer.Signer{} // Temporary signer for generation
	res, err := tempSigner.CreateWallet(body.MasterPIN)
	if err != nil {
		http.Error(w, err.Error(), 500)
		return
	}

	// 2. Sync to Cloud Relay - relay must acknowledge before anything is written to disk.
	// The uid is relay-assigned; a local uid has no corresponding share2 on the backend
	// and would cause post-restart signing to fail permanently.
	setupRelay := env("RELAY_URL", relayURL)
	setupBody, _ := json.Marshal(map[string]interface{}{
		"enc_share1":     res.Share1,
		"enc_share2":     res.Share2,
		"master_pub_key": res.MasterPubKey,
		"addresses":      res.Addresses,
	})
	sssClient := &http.Client{Timeout: 30 * time.Second}
	sssResp, sssErr := sssClient.Post(setupRelay+"/sss/setup", "application/json", bytes.NewBuffer(setupBody))
	if sssErr != nil {
		http.Error(w, "relay unavailable: "+sssErr.Error(), http.StatusBadGateway)
		return
	}
	defer sssResp.Body.Close()
	if sssResp.StatusCode != http.StatusOK && sssResp.StatusCode != http.StatusCreated {
		errBody, _ := io.ReadAll(io.LimitReader(sssResp.Body, 512))
		http.Error(w, fmt.Sprintf("relay setup failed (%d): %s", sssResp.StatusCode, strings.TrimSpace(string(errBody))), http.StatusBadGateway)
		return
	}
	var relayRes struct {
		UID string `json:"uid"`
	}
	json.NewDecoder(sssResp.Body).Decode(&relayRes)
	finalUID := strings.TrimSpace(relayRes.UID)
	if finalUID == "" {
		http.Error(w, "relay returned empty uid", http.StatusBadGateway)
		return
	}

	// 3. Relay confirmed - now write identity and shares to disk atomically
	masterPubKey = res.MasterPubKey
	addresses = normalizedWalletAddresses(res.Addresses)
	sekKey = newSEK
	remoteManagedWallet = false
	boundUid = finalUID
	encShare3 = res.Share3
	localShare2 = res.Share2

	idData, _ := json.Marshal(map[string]interface{}{
		"master_pub_key": masterPubKey,
		"addresses":      addresses,
		"uid":            boundUid,
		"wrapped_sek":    wrappedSEK,
		"agent_token":    env("AGENT_TOKEN", ""),
	})
	if err := utils.AtomicWrite(env("IDENTITY_PATH", "identity.json"), idData); err != nil {
		log.Printf("[claw wallet sandbox] Warning: failed to persist identity: %v", err)
	} else if policyEngine != nil {
		if err := policyEngine.Reload(); err != nil {
			log.Printf("[claw wallet sandbox] Warning: failed to migrate encrypted policy: %v", err)
		}
	}
	if err := EnsureWrappedSEKFile(env("IDENTITY_PATH", "identity.json"), wrappedSEK, env("AGENT_TOKEN", "")); err != nil {
		log.Printf("[claw wallet sandbox] Warning: failed to persist wrapped_sek.json: %v", err)
	}
	s3Data, _ := json.Marshal(res.Share3)
	if err := utils.AtomicWrite(env("SHARE3_PATH", "share3.json"), s3Data); err != nil {
		log.Printf("[claw wallet sandbox] Warning: failed to persist share3: %v", err)
	}
	log.Printf("[claw wallet sandbox] Wallet created and relay-synced: uid=%s addr=%s", boundUid, masterPubKey)

	// Use the SEK (not AGENT_TOKEN) to decrypt share3 for activation
	activationPIN := body.MasterPIN // body.MasterPIN is already the hex-encoded SEK
	if err := activateWithSharePINLocked(activationPIN); err != nil {
		lockedReason = "activation_failed"
		log.Printf("[claw wallet sandbox] Initial activation failed: %v", err)
	}

	// 5. Return results (Just what the agent needs: Address and UID)
	payload := walletInitResponsePayload(finalUID, walletStatusLocked(), res.Addresses, false, walletLockedReasonLocked())
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(payload)
}

func walletInitResponsePayload(uid, status string, rawAddresses map[string]string, existingIdentity bool, lockedReason string) map[string]interface{} {
	addresses := publicTrackedAddresses(rawAddresses)
	payload := map[string]interface{}{
		"address":   addresses["ethereum"],
		"addresses": addresses,
		"uid":       uid,
		"status":    status,
	}
	if existingIdentity {
		payload["existing_identity"] = true
	}
	if reason := strings.TrimSpace(lockedReason); reason != "" {
		payload["locked_reason"] = reason
	}
	return payload
}

func handleChallengeSign(w http.ResponseWriter, r *http.Request) {
	mu.RLock()
	s := activeSigner
	mu.RUnlock()

	if s == nil {
		http.Error(w, "Sandbox not activated", http.StatusUnauthorized)
		return
	}

	var body struct {
		Challenge string                `json:"challenge"`
		Share1    signer.EncryptedShare `json:"share1"`
		Share2    signer.EncryptedShare `json:"share2"`
	}
	if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
		http.Error(w, "bad request", 400)
		return
	}

	sig, err := s.SignChallenge(body.Challenge, &body.Share1, &body.Share2)
	if err != nil {
		http.Error(w, err.Error(), 500)
		return
	}

	w.Write([]byte(fmt.Sprintf(`{"signature": "%s"}`, sig)))
}

// handleRPCProxy proxies JSON-RPC requests to the target chain's RPC endpoint.
// URL: /api/rpc/{chain}   (e.g. /api/rpc/solana, /api/rpc/ethereum)
func handleRPCProxy(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "only POST supported", http.StatusMethodNotAllowed)
		return
	}

	chain := strings.ToLower(strings.TrimPrefix(r.URL.Path, "/api/rpc/"))
	chain = strings.Trim(chain, "/")
	if !isPublicChainEnabled(chain) {
		http.Error(w, publicChainDisabledMessage(chain), http.StatusBadRequest)
		return
	}
	rpcURLs := rpcProxyUpstreamURLs(chain)
	if len(rpcURLs) == 0 {
		http.Error(w, fmt.Sprintf("unsupported chain: %s", chain), http.StatusBadRequest)
		return
	}

	body, err := io.ReadAll(io.LimitReader(r.Body, 1<<20)) // 1 MB max
	if err != nil {
		http.Error(w, "failed to read request body", http.StatusBadRequest)
		return
	}

	allowFallback := rpcRequestAllowsFallback(body)
	resp, upstreamURL, err := doRPCProxyRequest(rpcURLs, body, allowFallback)
	if err != nil {
		http.Error(w, fmt.Sprintf("upstream RPC error: %v", err), http.StatusBadGateway)
		return
	}
	defer resp.Body.Close()
	if allowFallback && len(rpcURLs) > 1 {
		log.Printf("[claw wallet sandbox] RPC proxy chain=%s upstream=%s", chain, upstreamURL)
	}

	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(resp.StatusCode)
	io.Copy(w, resp.Body)
}

func handleWipe(w http.ResponseWriter, r *http.Request) {
	mu.Lock()
	defer mu.Unlock()
	ExpireActiveSessionLocked("manual_wipe")
	w.Write([]byte(`{"status": "memory_wiped"}`))
}

func handleSign(w http.ResponseWriter, r *http.Request) {
	mu.Lock()
	if sessionExpiredLocked() {
		ExpireActiveSessionLocked("ttl_expired")
	}
	isAct := activated
	s := activeSigner
	pe := policyEngine
	mu.Unlock()
	fmt.Printf("[claw wallet sandbox] Sign request received (active=%v)\n", activated)
	if !isAct {
		http.Error(w, "Locked", 401)
		return
	}

	var req signer.SignRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, "bad request", 400)
		return
	}
	req.Chain = strings.ToLower(strings.TrimSpace(req.Chain))
	req.SignMode = strings.TrimSpace(req.SignMode)
	if !isPublicChainEnabled(req.Chain) {
		http.Error(w, publicChainDisabledMessage(req.Chain), http.StatusBadRequest)
		return
	}
	activePolicy := pe.Current()
	isEVM := signer.IsEVMChain(req.Chain)
	var structuredBuild *EvmStructuredBuild

	if isEVM && strings.EqualFold(req.SignMode, "transaction") && strings.TrimSpace(req.TxPayloadHex) == "" && strings.TrimSpace(req.BuilderKind) != "" {
		mu.RLock()
		from := addresses["ethereum"]
		mu.RUnlock()
		if from == "" {
			http.Error(w, "wallet address unavailable for structured EVM builder", 500)
			return
		}
		build, err := buildStructuredEVMSigningPayload(req.Chain, from, &req)
		if err != nil {
			http.Error(w, err.Error(), 400)
			return
		}
		structuredBuild = build
		req.TxPayloadHex = build.TxPayloadHex
	}
	if !isEVM && strings.EqualFold(req.SignMode, "transaction") && strings.TrimSpace(req.TxPayloadHex) == "" && strings.TrimSpace(req.BuilderKind) != "" {
		http.Error(w, fmt.Sprintf("structured %s builder is not implemented yet", req.Chain), http.StatusNotImplemented)
		return
	}

	// Sui personal_sign: 自动补充 intent prefix [0x03, 0x00, 0x00]，兼容外部只传纯消息
	if strings.EqualFold(req.Chain, "sui") && strings.EqualFold(req.SignMode, "personal_sign") && strings.TrimSpace(req.TxPayloadHex) != "" {
		if msgBytes, err := DecodeHex(req.TxPayloadHex); err == nil {
			prefixed := signer.EnsureSuiPersonalSignIntentPrefix(msgBytes)
			if len(prefixed) != len(msgBytes) {
				req.TxPayloadHex = "0x" + hex.EncodeToString(prefixed)
			}
		}
	}

	if activePolicy.StrictPlainText && strings.EqualFold(req.SignMode, "personal_sign") {
		msgBytes, err := DecodeHex(req.TxPayloadHex)
		if err != nil {
			http.Error(w, "invalid tx_payload_hex", 400)
			return
		}
		if strings.EqualFold(req.Chain, "sui") {
			if err := signer.ValidateSuiPersonalSignMessage(msgBytes, activePolicy.PersonalSignKeywordBlacklist); err != nil {
				audit.LogEvent("tx_sign", req.UID, RuntimeSandboxLabel, "rejected", err.Error())
				http.Error(w, err.Error(), 403)
				return
			}
		} else {
			if err := signer.ValidateStrictPlainTextPayload(msgBytes, activePolicy.PersonalSignKeywordBlacklist); err != nil {
				audit.LogEvent("tx_sign", req.UID, RuntimeSandboxLabel, "rejected", err.Error())
				http.Error(w, err.Error(), 403)
				return
			}
		}
	}

	if !activePolicy.AllowBlindSign {
		assessment, err := signer.AssessAuditability(&req)
		if err != nil {
			http.Error(w, err.Error(), 400)
			return
		}
		if assessment.Enforceable && !assessment.Auditable {
			reason := "blind payload blocked"
			if assessment.Reason != "" {
				reason = assessment.Reason
			}
			audit.LogEvent("tx_sign", req.UID, RuntimeSandboxLabel, "rejected", reason)
			http.Error(w, reason, 403)
			return
		}
	}

	if isEVM && req.SignMode == "transaction" {
		txBytes, err := DecodeHex(req.TxPayloadHex)
		if err != nil {
			http.Error(w, "invalid tx_payload_hex", 400)
			return
		}
		intent, err := signer.DecodeEvmSigningPayloadIntent(txBytes)
		if err != nil {
			http.Error(w, err.Error(), 400)
			return
		}
		if intent.To == "" {
			http.Error(w, "contract creation is not allowed", 403)
			return
		}
		req.To = intent.To
		req.AmountWei = intent.ValueWei
		req.Data = intent.DataHex
	}

	pi := &policy.Intent{Chain: req.Chain, SignMode: req.SignMode, To: req.To, AmountWei: req.AmountWei}

	// 1.13: ERC20 Transfer Detection for Risk Control
	if isEVM && strings.HasPrefix(req.Data, "0xa9059cbb") && len(req.Data) >= 138 {
		// Extract recipient and amount from ERC20 transfer(address,uint256)
		// 0xa9059cbb + 32-byte addr + 32-byte amount
		toPart := req.Data[34:74] // skip 0xa9059cbb + 24 leading zeroes for address
		amtPart := strings.TrimLeft(req.Data[74:138], "0")
		if amtPart == "" {
			amtPart = "0"
		}

		val, _ := new(big.Int).SetString(amtPart, 16)
		req.TokenContract = req.To
		req.To = "0x" + toPart
		req.AmountWei = val.String()
		pi.TokenContract = req.TokenContract
		pi.To = req.To
		pi.AmountWei = req.AmountWei
	}

	mu.RLock()
	intentSnapshot := make(map[string]string, len(addresses))
	for k, v := range addresses {
		intentSnapshot[k] = v
	}
	mu.RUnlock()
	if err := validateIntentWithRefreshForEvent(pe, pi, intentSnapshot, req.UID, "tx_sign"); err != nil {
		http.Error(w, err.Error(), 403)
		return
	}

	// Only request share2 after the local policy engine has accepted the intent.
	// This avoids sending locally blocked transactions to the backend approval gate.
	if err := PopulateSigningShares(&req); err != nil {
		audit.LogEvent("tx_sign", req.UID, RuntimeSandboxLabel, "failed", "share2 recovery: "+err.Error())
		if gateErr, ok := err.(*Share2GateError); ok {
			http.Error(w, gateErr.reason, gateErr.status)
			return
		}
		http.Error(w, err.Error(), http.StatusBadGateway)
		return
	}

	needsTransferChecks := strings.TrimSpace(req.SignMode) == "" || strings.EqualFold(req.SignMode, "transaction")
	postSignRefreshChain := ""
	postSignRefreshAddress := ""
	if needsTransferChecks {
		mu.RLock()
		snapshot := make(map[string]string, len(addresses))
		for k, v := range addresses {
			snapshot[k] = v
		}
		mu.RUnlock()
		for chainName, address := range buildUsageRefreshSnapshot(pi.Chain, snapshot) {
			postSignRefreshChain = chainName
			postSignRefreshAddress = address
		}
		_ = ensureFreshUsageFacts(pi.Chain, snapshot, "tx_sign")
	}

	res, err := s.Sign(&req)
	if err != nil {
		audit.LogEvent("tx_sign", req.UID, RuntimeSandboxLabel, "failed", err.Error())
		http.Error(w, err.Error(), 500)
		return
	}
	if structuredBuild != nil {
		res.TxPayloadHex = structuredBuild.TxPayloadHex
		res.BuilderKind = structuredBuild.BuilderKind
		if rawTxHex, err := AssembleSignedLegacyEVMTransaction(structuredBuild, res.SignatureHex); err == nil {
			res.RawTxHex = rawTxHex
		}
	}
	pe.Commit(pi)
	if needsTransferChecks && postSignRefreshChain != "" && postSignRefreshAddress != "" {
		asyncRefreshUsageFactsForPolicy(postSignRefreshChain, postSignRefreshAddress)
	}
	audit.LogEvent("tx_sign", req.UID, RuntimeSandboxLabel, "accepted", fmt.Sprintf("chain=%s, to=%s, amt=%s", pi.Chain, pi.To, pi.AmountWei))
	json.NewEncoder(w).Encode(res)
}

// 助手函数
func readOptionalJSONFile(path string) (interface{}, error) {
	var (
		data []byte
		err  error
	)
	if path == env("POLICY_PATH", "policy.json") {
		data, err = policy.ReadStoredPolicyBytes(path)
	} else {
		data, err = os.ReadFile(path)
	}
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return nil, nil
		}
		return nil, err
	}
	var payload interface{}
	if err := json.Unmarshal(data, &payload); err != nil {
		return nil, err
	}
	return payload, nil
}

func DecodeHex(s string) ([]byte, error) {
	return hex.DecodeString(strings.TrimPrefix(s, "0x"))
}

func gatewayStatusLabel(status string) string {
	switch strings.ToLower(strings.TrimSpace(status)) {
	case "ready":
		return "active"
	case "inactive":
		return "offline"
	default:
		return "locked"
	}
}

func canReactivateLocallyLocked() bool {
	return masterPubKey != "" && !activated && !remoteManagedWallet && hasLegacyLocalShareLocked()
}

func absPathOrValue(path string) string {
	path = strings.TrimSpace(path)
	if path == "" {
		return ""
	}
	abs, err := filepath.Abs(path)
	if err != nil {
		return path
	}
	return abs
}

func fetchRelayWalletBindingStatus(uid string) (string, bool) {
	uid = strings.TrimSpace(uid)
	if uid == "" {
		return "unknown", false
	}
	req, err := http.NewRequest(http.MethodGet, relayURL+"/wallet/status?uid="+url.QueryEscape(uid), nil)
	if err != nil {
		return "unknown", false
	}
	client := &http.Client{Timeout: 1500 * time.Millisecond}
	resp, err := client.Do(req)
	if err != nil {
		return "unknown", false
	}
	defer resp.Body.Close()

	var payload struct {
		Status string `json:"status"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&payload); err != nil {
		return "unknown", false
	}
	status := strings.ToLower(strings.TrimSpace(payload.Status))
	return status, status == "valid"
}

func addressExplorersLocked() map[string]string {
	out := make(map[string]string)
	for chain, addr := range publicTrackedAddresses(addresses) {
		if link := assets.ExplorerAddressURL(chain, addr); link != "" {
			out[chain] = link
		}
	}
	return out
}

func importProvisionedWalletLocked(uid, pubKey string, addr map[string]string, share1 signer.EncryptedShare) error {
	uid = strings.TrimSpace(uid)
	pubKey = strings.TrimSpace(pubKey)
	if uid == "" || pubKey == "" || share1.Cipher == "" {
		return errors.New("uid, master_pub_key, and enc_share3 are required")
	}
	if masterPubKey != "" && masterPubKey != pubKey {
		return errors.New("sandbox already has a different wallet identity; reset before importing")
	}
	if addresses == nil {
		addresses = map[string]string{}
	}
	if len(addr) > 0 {
		addresses = normalizedWalletAddresses(addr)
	}
	masterPubKey = pubKey
	boundUid = uid
	encShare1 = signer.EncryptedShare{}
	encShare3 = share1
	localShare2 = signer.EncryptedShare{}
	sekKey = nil
	remoteManagedWallet = true
	if activeSigner != nil {
		activeSigner.Wipe()
		activeSigner = nil
	}
	activated = false
	lockedReason = "waiting_for_pin"
	pinExpiry = time.Time{}

	share3Data, _ := json.Marshal(share1)
	if err := utils.AtomicWrite(env("SHARE3_PATH", "share3.json"), share3Data); err != nil {
		return fmt.Errorf("failed to persist share3: %w", err)
	}
	_ = os.Remove(env("SHARE1_PATH", "share1.json"))

	type identityMirror struct {
		WrappedSEK string `json:"wrapped_sek,omitempty"`
		AgentToken string `json:"agent_token,omitempty"`
	}
	identityPath := env("IDENTITY_PATH", "identity.json")
	if data, err := os.ReadFile(identityPath); err == nil {
		var mirror identityMirror
		if json.Unmarshal(data, &mirror) == nil && strings.TrimSpace(mirror.WrappedSEK) != "" {
			if err := EnsureWrappedSEKFile(identityPath, mirror.WrappedSEK, mirror.AgentToken); err != nil {
				log.Printf("[claw wallet sandbox] Warning: failed to persist wrapped_sek.json: %v", err)
			}
		}
	}
	idData, _ := json.Marshal(map[string]any{
		"master_pub_key": masterPubKey,
		"addresses":      addresses,
		"uid":            boundUid,
		"agent_token":    env("AGENT_TOKEN", ""),
	})
	if err := utils.AtomicWrite(identityPath, idData); err != nil {
		return fmt.Errorf("failed to persist identity: %w", err)
	}
	log.Printf("[claw wallet sandbox] Imported provisioned wallet uid=%s", boundUid)
	return nil
}

func walletStatusLocked() string {
	if activated {
		return "ready"
	}
	if remoteManagedWallet || hasRemoteManagedShareLocked() {
		return "provisioned_waiting_for_pin"
	}
	if masterPubKey != "" {
		return "identity_set_waiting_for_activation"
	}
	return "inactive"
}

func walletLockedReasonLocked() string {
	if activated {
		return ""
	}
	if remoteManagedWallet || hasRemoteManagedShareLocked() {
		if lockedReason != "" {
			return lockedReason
		}
		return "waiting_for_pin"
	}
	if masterPubKey != "" {
		if lockedReason != "" {
			return lockedReason
		}
		return "waiting_for_activation"
	}
	return ""
}

func hasRemoteManagedShareLocked() bool {
	return remoteManagedWallet && masterPubKey != "" && encShare3.Cipher != ""
}

func hasLegacyLocalShareLocked() bool {
	return !remoteManagedWallet && masterPubKey != "" && encShare3.Cipher != "" && len(sekKey) > 0
}

func applyPINResidencyLocked() {
	ttl := int64(86400)
	if policyEngine != nil {
		ttl = policyEngine.GetTTL()
	}
	if ttl == 0 {
		pinExpiry = time.Time{}
		return
	}
	pinExpiry = time.Now().Add(time.Duration(ttl) * time.Second)
}

func reconcilePINResidencyLockedOnPolicyChange() {
	if !activated || policyEngine == nil {
		return
	}

	ttl := policyEngine.GetTTL()
	if ttl <= 0 {
		return
	}

	targetExpiry := time.Now().Add(time.Duration(ttl) * time.Second)
	if pinExpiry.IsZero() || pinExpiry.After(targetExpiry) {
		pinExpiry = targetExpiry
	}
}

func policiesEqualForSync(current, next policy.Policy) bool {
	return reflect.DeepEqual(current, next)
}

func sessionExpiredLocked() bool {
	if !activated {
		return false
	}
	ttl := int64(86400)
	if policyEngine != nil {
		ttl = policyEngine.GetTTL()
	}
	if ttl == 0 || pinExpiry.IsZero() {
		return false
	}
	return time.Now().After(pinExpiry)
}

func currentPINResidencyLocked() (*int64, bool) {
	if !activated || policyEngine == nil {
		return nil, false
	}
	ttl := policyEngine.GetTTL()
	if ttl == 0 {
		return nil, true
	}
	if pinExpiry.IsZero() {
		return nil, false
	}
	remaining := time.Until(pinExpiry)
	if remaining <= 0 {
		zero := int64(0)
		return &zero, false
	}
	seconds := int64((remaining + time.Second - 1) / time.Second)
	return &seconds, false
}

func ExpireActiveSessionLocked(reason string) {
	if activeSigner != nil {
		activeSigner.Wipe()
		activeSigner = nil
	}
	if !(reason == "ttl_expired" && policyEngine != nil && policyEngine.KeepShare2ResidentEnabled()) {
		localShare2 = signer.EncryptedShare{}
	}
	activated = false
	ephemeralPriv = nil
	pinExpiry = time.Time{}
	if reason != "" {
		lockedReason = reason
	}
}

func respondWalletStateLocked(w http.ResponseWriter) {
	payload := map[string]any{
		"status":                              walletStatusLocked(),
		"uid":                                 boundUid,
		"address":                             addresses["ethereum"],
		"addresses":                           publicTrackedAddresses(addresses),
		"master_pub_key":                      masterPubKey,
		"has_provisioned_share1":              hasRemoteManagedShareLocked(),
		"asset_refresh_state":                 filterPublicRefreshState(assets.RefreshStateSnapshot()),
		"asset_auto_refresh_interval_seconds": assets.AutoRefreshIntervalSeconds(),
	}
	if reason := walletLockedReasonLocked(); reason != "" {
		payload["locked_reason"] = reason
	}
	if activated && !pinExpiry.IsZero() {
		payload["pin_residency_expires_at"] = pinExpiry.UTC().Format(time.RFC3339)
	}
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(payload)
}

func activateWithSharePINLocked(sharePIN string) error {
	if masterPubKey == "" {
		return errors.New("wallet identity not initialized")
	}
	if encShare3.Cipher == "" {
		return errors.New("encrypted share3 is unavailable")
	}

	curve := ecdh.P256()
	priv, err := curve.GenerateKey(rand.Reader)
	if err != nil {
		return err
	}
	actives, err := signer.New(encShare3, sharePIN, priv, masterPubKey)
	if err != nil {
		return err
	}

	ephemeralPriv = priv
	activeSigner = actives
	activated = true
	lockedReason = ""
	applyPINResidencyLocked()

	go func(uid string, priv *ecdh.PrivateKey) {
		if err := postAgentSyncForUID(uid, priv); err != nil {
			log.Printf("[claw wallet sandbox] post agent sync after activation failed: %v", err)
			return
		}
		prefetchRelayPINFromLastSync(uid, priv)
	}(strings.TrimSpace(boundUid), priv)
	return nil
}

func activateProvisionedPINLocked(pin string) error {
	if masterPubKey == "" {
		return errors.New("wallet identity not initialized")
	}
	if !hasRemoteManagedShareLocked() {
		return errors.New("encrypted remote share3 is unavailable")
	}

	curve := ecdh.P256()
	priv, err := curve.GenerateKey(rand.Reader)
	if err != nil {
		return err
	}
	actives, err := signer.New(encShare3, pin, priv, masterPubKey)
	if err != nil {
		return err
	}

	if activeSigner != nil {
		activeSigner.Wipe()
	}
	ephemeralPriv = priv
	activeSigner = actives
	activated = true
	lockedReason = ""
	applyPINResidencyLocked()

	go func(uid string, priv *ecdh.PrivateKey) {
		if err := postAgentSyncForUID(uid, priv); err != nil {
			log.Printf("[claw wallet sandbox] post agent sync after activation failed: %v", err)
			return
		}
		prefetchRelayPINFromLastSync(uid, priv)
	}(strings.TrimSpace(boundUid), priv)
	return nil
}

func sandboxRuntimeMetricsSnapshot() sandboxRuntimeMetrics {
	mu.Lock()
	defer mu.Unlock()

	if sessionExpiredLocked() {
		ExpireActiveSessionLocked("ttl_expired")
	}

	status := "locked"
	if activated {
		status = "active"
	}
	ttlRemainingSeconds, ttlUnlimited := currentPINResidencyLocked()
	todaySpentUSD := 0.0
	todayTxCount := 0
	if policyEngine != nil {
		todaySpentUSD = policyEngine.TodaySpentUSD()
		todayTxCount = policyEngine.TodayTxCount()
	}
	return sandboxRuntimeMetrics{
		Status:              status,
		TTLRemainingSeconds: ttlRemainingSeconds,
		TTLUnlimited:        ttlUnlimited,
		TodayTxCount:        todayTxCount,
		TodaySpentUSD:       todaySpentUSD,
	}
}

func currentSandboxRuntimeStatus() string {
	return sandboxRuntimeMetricsSnapshot().Status
}

func refreshSandboxHeartbeat(uid string, priv *ecdh.PrivateKey) {
	uid = strings.TrimSpace(uid)
	if uid == "" || priv == nil {
		return
	}
	if err := publishSandboxConnect(uid, priv); err != nil {
		log.Printf("[claw wallet sandbox] sandbox state refresh failed uid=%s: %v", uid, err)
	}
}

func publishSandboxConnect(uid string, priv *ecdh.PrivateKey) error {
	if priv == nil {
		return errors.New("ephemeral unlock key is unavailable")
	}
	if err := postAgentSyncForUID(uid, priv); err != nil {
		return err
	}
	snap := agentSyncSnapshot()
	if err := processRemotePolicySyncFromSnapshot(uid, snap.Policy); err != nil {
		return err
	}
	prefetchRelayPINFromLastSync(uid, priv)
	return nil
}

// consumeRelayPIN returns decrypted PIN from in-memory prefetch cache (fromCache=true) or from POST /agent/sync (fromCache=false).
func consumeRelayPIN(uid string, priv *ecdh.PrivateKey) (pin string, ok bool, fromCache bool, err error) {
	if priv == nil {
		return "", false, false, errors.New("ephemeral unlock key is unavailable")
	}
	uid = strings.TrimSpace(uid)
	mu.Lock()
	if p, hit := relayPINCache[uid]; hit && strings.TrimSpace(p) != "" {
		delete(relayPINCache, uid)
		mu.Unlock()
		return p, true, true, nil
	}
	mu.Unlock()
	if err := postAgentSyncForUID(uid, priv); err != nil {
		return "", false, false, err
	}
	agentSyncMu.RLock()
	pinObj := lastAgentSync.EncryptedPIN
	agentSyncMu.RUnlock()
	if pinObj == nil || pinObj.EncryptedPINHex == "" {
		return "", false, false, nil
	}
	pin, err = decryptRelayPIN(priv, pinObj.EncryptedPINHex, pinObj.NonceHex)
	if err != nil {
		return "", false, false, err
	}
	return pin, true, false, nil
}

func restoreRelayPINCache(uid string, pin string) {
	mu.Lock()
	defer mu.Unlock()
	if strings.TrimSpace(uid) == "" || strings.TrimSpace(pin) == "" {
		return
	}
	relayPINCache[uid] = pin
}

// postAgentUnlockComplete notifies relay that local unlock succeeded; retries on transient errors.
func postAgentUnlockComplete(uid string) error {
	uid = strings.TrimSpace(uid)
	body, err := json.Marshal(map[string]string{"uid": uid})
	if err != nil {
		return err
	}
	var lastErr error
	for attempt := 0; attempt < 8; attempt++ {
		if attempt > 0 {
			time.Sleep(time.Duration(attempt) * time.Second)
		}
		resp, err := http.Post(relayURL+"/agent/unlock/complete", "application/json", bytes.NewReader(body))
		if err != nil {
			lastErr = err
			log.Printf("[claw wallet sandbox] unlock complete POST error uid=%s attempt=%d err=%v", uid, attempt+1, err)
			continue
		}
		respBody, _ := io.ReadAll(io.LimitReader(resp.Body, 4096))
		resp.Body.Close()
		if resp.StatusCode >= 200 && resp.StatusCode < 300 {
			return nil
		}
		lastErr = fmt.Errorf("HTTP %d: %s", resp.StatusCode, strings.TrimSpace(string(respBody)))
		log.Printf("[claw wallet sandbox] unlock complete rejected uid=%s attempt=%d status=%d body=%s", uid, attempt+1, resp.StatusCode, strings.TrimSpace(string(respBody)))
	}
	if lastErr != nil {
		return lastErr
	}
	return fmt.Errorf("unlock complete failed after retries")
}

func fetchWrappedShare2ForUID(uid string) (string, string, error) {
	url := fmt.Sprintf("%s/agent/recovery_share2?uid=%s", relayURL, url.QueryEscape(uid))
	resp, err := (&http.Client{Timeout: 10 * time.Second}).Get(url)
	if err != nil {
		return "", "", err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(io.LimitReader(resp.Body, 2048))
		return "", "", fmt.Errorf("share2 fetch failed: %s", strings.TrimSpace(string(body)))
	}
	var sr struct {
		WrappedShare2 string `json:"wrapped_share2_hex"`
		Nonce         string `json:"nonce_hex"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&sr); err != nil {
		return "", "", err
	}
	return sr.WrappedShare2, sr.Nonce, nil
}

func cacheWrappedShare2ForSessionIfAllowed(wrappedShare2, share2Nonce string) {
	if wrappedShare2 == "" || share2Nonce == "" || policyEngine == nil || !policyEngine.KeepShare2ResidentEnabled() {
		return
	}

	mu.RLock()
	priv := ephemeralPriv
	mu.RUnlock()
	if priv == nil {
		return
	}

	inner, err := signer.UnwrapWrappedEncryptedShare(priv, wrappedShare2, share2Nonce)
	if err != nil {
		log.Printf("[claw wallet sandbox] share2 cache skipped: %v", err)
		return
	}

	mu.Lock()
	localShare2 = inner
	mu.Unlock()
}

// buildShare2IntentPayload 构建Share2意图负载 审批后使用
func buildShare2IntentPayload(req *signer.SignRequest) string {
	if req == nil {
		return ""
	}
	payload := struct {
		UID            string          `json:"uid,omitempty"`
		Chain          string          `json:"chain"`
		SignMode       string          `json:"sign_mode"`
		DerivationPath string          `json:"derivation_path,omitempty"`
		BuilderKind    string          `json:"builder_kind,omitempty"`
		To             string          `json:"to,omitempty"`
		TokenContract  string          `json:"token_contract,omitempty"`
		AmountWei      string          `json:"amount_wei,omitempty"`
		Data           string          `json:"data,omitempty"`
		TxPayloadHex   string          `json:"tx_payload_hex,omitempty"`
		TypedData      json.RawMessage `json:"typed_data,omitempty"`
		ApprovalID     string          `json:"approval_id,omitempty"`
	}{
		UID:            strings.TrimSpace(req.UID),
		Chain:          strings.ToLower(strings.TrimSpace(req.Chain)),
		SignMode:       strings.TrimSpace(req.SignMode),
		DerivationPath: strings.TrimSpace(req.DerivationPath),
		BuilderKind:    strings.TrimSpace(req.BuilderKind),
		To:             strings.TrimSpace(req.To),
		TokenContract:  strings.TrimSpace(req.TokenContract),
		AmountWei:      strings.TrimSpace(req.AmountWei),
		Data:           strings.TrimSpace(req.Data),
		TxPayloadHex:   strings.TrimSpace(req.TxPayloadHex),
		TypedData:      req.TypedData,
		ApprovalID:     strings.TrimSpace(req.ApprovalID),
	}
	raw, err := json.Marshal(payload)
	if err != nil {
		return ""
	}
	return string(raw)
}

// requestWrappedShare2ForSigning 请求Share2签名
func requestWrappedShare2ForSigning(req *signer.SignRequest) (string, string, error) {
	if req == nil {
		return "", "", errors.New("missing sign request")
	}
	uid := strings.TrimSpace(req.UID)
	if uid == "" {
		mu.RLock()
		uid = strings.TrimSpace(boundUid)
		mu.RUnlock()
	}
	mu.RLock()
	currentPriv := ephemeralPriv
	mu.RUnlock()
	if uid != "" && currentPriv != nil {
		// Re-register the current sandbox session key before requesting share2.
		// This makes post-restart signing resilient even if backend relay state was lost.
		if err := publishSandboxConnect(uid, currentPriv); err != nil {
			return "", "", fmt.Errorf("sandbox connect refresh failed: %w", err)
		}
	}

	body, _ := json.Marshal(share2GateRelayRequest{
		UID:             uid,
		Chain:           strings.ToLower(strings.TrimSpace(req.Chain)),
		SignMode:        strings.TrimSpace(req.SignMode),
		ConfirmedByUser: req.ConfirmedByUser,
		IsUserApproval:  req.IsUserApproval,
		ApprovalID:      strings.TrimSpace(req.ApprovalID),
		ExecutionToken:  strings.TrimSpace(req.ExecutionToken),
		IntentPayload:   buildShare2IntentPayload(req),
		Audit:           buildShare2AuditSummary(req),
	})
	resp, err := (&http.Client{Timeout: 10 * time.Second}).Post(
		relayURL+"/agent/recovery_share2",
		"application/json",
		bytes.NewReader(body),
	)
	if err != nil {
		return "", "", err
	}
	defer resp.Body.Close()

	var payload share2GateRelayResponse
	if err := json.NewDecoder(resp.Body).Decode(&payload); err != nil {
		return "", "", err
	}
	switch resp.StatusCode {
	case http.StatusOK:
		cacheWrappedShare2ForSessionIfAllowed(payload.WrappedShare2, payload.Nonce)
		return payload.WrappedShare2, payload.Nonce, nil
	case http.StatusConflict, http.StatusForbidden:
		reason := strings.TrimSpace(payload.Reason)
		if reason == "" {
			reason = strings.TrimSpace(payload.Error)
		}
		if reason == "" {
			reason = "backend share2 gate rejected the signing request"
		}
		return "", "", &Share2GateError{status: resp.StatusCode, reason: reason}
	default:
		reason := strings.TrimSpace(payload.Reason)
		if reason == "" {
			reason = strings.TrimSpace(payload.Error)
		}
		if reason == "" {
			reason = fmt.Sprintf("share2 request failed with status %d", resp.StatusCode)
		}
		return "", "", errors.New(reason)
	}
}

func buildShare2AuditSummary(req *signer.SignRequest) share2AuditSummary {
	if req == nil {
		return share2AuditSummary{}
	}
	summary := share2AuditSummary{
		To:            strings.TrimSpace(req.To),
		AmountWei:     strings.TrimSpace(req.AmountWei),
		TokenContract: strings.TrimSpace(req.TokenContract),
		DecodedMethod: strings.TrimSpace(req.BuilderKind),
		RiskFlags:     []string{},
	}
	mode := strings.ToLower(strings.TrimSpace(req.SignMode))

	switch mode {
	case "personal_sign":
		msgBytes, err := DecodeHex(req.TxPayloadHex)
		if err == nil {
			previewBytes := msgBytes
			validateErr := signer.ValidateStrictPlainTextPayload(msgBytes, nil)
			if strings.EqualFold(req.Chain, "sui") {
				validateErr = signer.ValidateSuiPersonalSignMessage(msgBytes, nil)
				if validateErr == nil && len(msgBytes) >= 3 {
					previewBytes = msgBytes[3:]
				}
			}
			if validateErr == nil {
				summary.IsPlainText = true
				msg := string(previewBytes)
				if len(msg) > 160 {
					msg = msg[:160]
				}
				summary.MessagePreview = msg
			}
		}
	case "", "transaction":
		if summary.DecodedMethod == "" {
			if summary.TokenContract != "" && !strings.EqualFold(summary.TokenContract, "native") {
				summary.DecodedMethod = "token_transfer"
			} else if summary.To != "" {
				summary.DecodedMethod = "transaction"
			}
		}
		if summary.TokenContract != "" && !strings.EqualFold(summary.TokenContract, "native") {
			summary.ContractAddr = summary.TokenContract
		} else if summary.To != "" && strings.TrimSpace(req.Data) != "" && req.Data != "0x" {
			summary.ContractAddr = summary.To
		}
		summary.AmountUSD = estimateIntentUSD(req)
		// TODO: 不在sandbox中询价 使用后端服务的okx进行价格换算
		// summary.AmountUSD = 0
		if contract := strings.TrimSpace(summary.ContractAddr); contract != "" {
			tokenRisk := security.CheckTokenRisk(req.Chain, contract)
			switch {
			case tokenRisk.RiskLevel >= 4:
				summary.RiskFlags = append(summary.RiskFlags, "high_risk_contract")
			case tokenRisk.RiskLevel >= 3:
				summary.RiskFlags = append(summary.RiskFlags, "medium_risk_contract")
			}
		}
	}

	return summary
}

func estimateIntentUSD(req *signer.SignRequest) float64 {
	if req == nil {
		return 0
	}
	amtF, err := strconv.ParseFloat(strings.TrimSpace(req.AmountWei), 64)
	if err != nil || amtF <= 0 {
		return 0
	}

	var (
		price float64
		ok    bool
	)
	if contract := strings.TrimSpace(req.TokenContract); contract != "" && !strings.EqualFold(contract, "native") {
		price, ok = oracle.GetToken(req.Chain, contract, "unknown")
	} else {
		price, ok = oracle.Get(req.Chain)
	}
	if !ok || price <= 0 {
		return 0
	}

	decimals := assets.TokenDecimals(req.Chain, req.TokenContract)
	divisor := 1.0
	for i := 0; i < decimals; i++ {
		divisor *= 10
	}
	return (amtF / divisor) * price
}

func decryptEnvelope(priv *ecdh.PrivateKey, encHex, nonceHex string) ([]byte, error) {
	data, _ := hex.DecodeString(encHex)
	nonce, _ := hex.DecodeString(nonceHex)
	browserPub, _ := ecdh.P256().NewPublicKey(data[:65])
	secret, _ := priv.ECDH(browserPub)
	hk := hkdf.New(sha256.New, secret, nil, []byte("CLAY-POLICY-UPDATE"))
	key := make([]byte, 32)
	io.ReadFull(hk, key)
	return gc.DecryptData(key, data[65:], nonce)
}

func submitSignSessionResult(signID string, success bool, resultPayload json.RawMessage, errText string) {
	status := "completed"
	if !success {
		status = "failed"
	}
	body, _ := json.Marshal(map[string]any{
		"sign_id":        signID,
		"status":         status,
		"result_payload": resultPayload,
		"error":          strings.TrimSpace(errText),
	})
	resp, err := http.Post(relayURL+"/api/v1/agent/sign/submit", "application/json", bytes.NewReader(body))
	if err != nil {
		log.Printf("[claw wallet sandbox] Sign session submit failed for %s: %v", signID, err)
		return
	}
	if resp != nil && resp.Body != nil {
		io.Copy(io.Discard, resp.Body)
		resp.Body.Close()
	}
}

func validateSandboxPolicyPayload(raw json.RawMessage) (policy.Policy, error) {
	current := policyEngine.Current()
	next := current
	if err := json.Unmarshal(raw, &next); err != nil {
		return policy.Policy{}, fmt.Errorf("invalid sandbox policy payload: %w", err)
	}
	return next, nil
}

func submitPolicySyncResult(uid string, applied bool, errText string) {
	body, _ := json.Marshal(map[string]string{
		"uid":    uid,
		"status": map[bool]string{true: "applied", false: "failed"}[applied],
		"error":  strings.TrimSpace(errText),
	})
	resp, err := http.Post(relayURL+"/agent/policy/complete", "application/json", bytes.NewReader(body))
	if err == nil && resp != nil && resp.Body != nil {
		io.Copy(io.Discard, resp.Body)
		resp.Body.Close()
	}
}

func decryptRelayPIN(priv *ecdh.PrivateKey, encHex, nonceHex string) (string, error) {
	data, err := DecodeHex(encHex)
	if err != nil {
		return "", err
	}
	nonce, err := DecodeHex(nonceHex)
	if err != nil {
		return "", err
	}
	browserPub, _ := ecdh.P256().NewPublicKey(data[:65])
	secret, _ := priv.ECDH(browserPub)
	hk := hkdf.New(sha256.New, secret, nil, []byte("CLAY-SIGNER-PIN"))
	key := make([]byte, 32)
	io.ReadFull(hk, key)
	plain, err := gc.DecryptData(key, data[65:], nonce)
	return string(plain), err
}

func SnapshotAddresses() map[string]string {
	mu.RLock()
	defer mu.RUnlock()
	snapshot := make(map[string]string, len(addresses))
	for k, v := range normalizedWalletAddresses(addresses) {
		snapshot[k] = v
	}
	return snapshot
}

func env(k, f string) string {
	if v := os.Getenv(k); v != "" {
		return v
	}
	return f
}

// 沙箱封控
func validateIntentWithRefreshForEvent(pe *policy.Engine, intent *policy.Intent, snapshot map[string]string, uid, eventType string) error {
	if err := pe.Validate(intent); err != nil {
		audit.LogEvent(eventType, uid, RuntimeSandboxLabel, "rejected", err.Error())
		reportLocalBlockedIntent(uid, intent, err.Error())
		return err
	}

	if err := ensureFreshUsageFacts(intent.Chain, snapshot, "tx_transfer"); err != nil {
		audit.LogEvent(eventType, uid, RuntimeSandboxLabel, "rejected", err.Error())
		return err
	}
	if err := pe.Validate(intent); err != nil {
		audit.LogEvent(eventType, uid, RuntimeSandboxLabel, "rejected", "post-refresh: "+err.Error())
		reportLocalBlockedIntent(uid, intent, err.Error())
		return err
	}
	return nil
}
