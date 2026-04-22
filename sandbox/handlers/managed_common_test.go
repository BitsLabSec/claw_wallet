package handlers

import (
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"sandbox/internals/policy"
	"strings"
	"sync"
	"testing"
	"time"
)

func newTestPolicyEngine(t *testing.T) *policy.Engine {
	t.Helper()
	dir := t.TempDir()
	policyPath := filepath.Join(dir, "policy.json")
	raw, err := json.Marshal(policy.Policy{})
	if err != nil {
		t.Fatalf("marshal policy: %v", err)
	}
	if err := os.WriteFile(policyPath, raw, 0600); err != nil {
		t.Fatalf("write policy: %v", err)
	}
	engine, err := policy.NewEngine(policyPath)
	if err != nil {
		t.Fatalf("new policy engine: %v", err)
	}
	return engine
}

func TestEnsureFreshUsageFactsSchedulesAsyncRefreshWithoutBlocking(t *testing.T) {
	oldAsyncOne := asyncRefreshOneForPolicy
	oldAsyncUsage := asyncRefreshUsageFactsForPolicy
	t.Cleanup(func() {
		asyncRefreshOneForPolicy = oldAsyncOne
		asyncRefreshUsageFactsForPolicy = oldAsyncUsage
	})

	refreshOneCalls := 0
	refreshUsageCalls := 0
	asyncRefreshOneForPolicy = func(chain, address string) {
		if chain != "ethereum" || address != "0xabc" {
			t.Fatalf("unexpected full refresh target %s/%s", chain, address)
		}
		refreshOneCalls++
	}
	asyncRefreshUsageFactsForPolicy = func(chain, address string) {
		if chain != "ethereum" || address != "0xabc" {
			t.Fatalf("unexpected usage refresh target %s/%s", chain, address)
		}
		refreshUsageCalls++
	}

	if err := ensureFreshUsageFacts("ethereum", map[string]string{"ethereum": "0xabc"}, "test"); err != nil {
		t.Fatalf("expected non-blocking usage refresh, got %v", err)
	}
	if refreshOneCalls != 1 {
		t.Fatalf("expected one async full refresh call, got %d", refreshOneCalls)
	}
	if refreshUsageCalls != 1 {
		t.Fatalf("expected one async usage refresh call, got %d", refreshUsageCalls)
	}
}

func TestBuildUsageRefreshSnapshotUsesCurrentChain(t *testing.T) {
	got := buildUsageRefreshSnapshot("solana", map[string]string{
		"ethereum": "0xabc",
		"solana":   "sol-address",
		"bitcoin":  "btc-address",
	})
	if len(got) != 1 || got["solana"] != "sol-address" {
		t.Fatalf("expected only solana snapshot, got %+v", got)
	}
}

func TestBuildUsageRefreshSnapshotFallsBackToEthereumForEVMChains(t *testing.T) {
	got := buildUsageRefreshSnapshot("0g", map[string]string{
		"ethereum": "0xabc",
		"bitcoin":  "btc-address",
	})
	if len(got) != 1 || got["0g"] != "0xabc" {
		t.Fatalf("expected 0g to reuse ethereum address, got %+v", got)
	}

	got = buildUsageRefreshSnapshot("kite", map[string]string{
		"ethereum": "0xabc",
		"bitcoin":  "btc-address",
	})
	if len(got) != 1 || got["kite"] != "0xabc" {
		t.Fatalf("expected kite to reuse ethereum address, got %+v", got)
	}

	got = buildUsageRefreshSnapshot("tempo", map[string]string{
		"ethereum": "0xabc",
		"bitcoin":  "btc-address",
	})
	if len(got) != 1 || got["tempo"] != "0xabc" {
		t.Fatalf("expected tempo to reuse ethereum address, got %+v", got)
	}
}

func TestNormalizedWalletAddressesAddsTempoAndKiteAliases(t *testing.T) {
	got := normalizedWalletAddresses(map[string]string{
		"ethereum": "0xabc",
	})
	if got["kite"] != "0xabc" {
		t.Fatalf("expected kite alias to reuse ethereum address, got %+v", got)
	}
	if got["tempo"] != "0xabc" {
		t.Fatalf("expected tempo alias to reuse ethereum address, got %+v", got)
	}
}

func TestWalletInitResponsePayloadNormalizesAddresses(t *testing.T) {
	payload := walletInitResponsePayload(
		"uid-123",
		"ready",
		map[string]string{
			"ethereum": "0xabc",
			"tron":     "TQzD9a6c3aVb1Q4o6y8P4Ff6dQGmW3qJ7v",
		},
		true,
		" locked ",
	)

	if payload["address"] != "0xabc" {
		t.Fatalf("expected ethereum address to be exposed as address, got %+v", payload["address"])
	}
	addresses, ok := payload["addresses"].(map[string]string)
	if !ok {
		t.Fatalf("expected normalized addresses map, got %+v", payload["addresses"])
	}
	if addresses["kite"] != "0xabc" {
		t.Fatalf("expected kite alias to be included, got %+v", addresses)
	}
	if addresses["tempo"] != "0xabc" {
		t.Fatalf("expected tempo alias to be included, got %+v", addresses)
	}
	if _, ok := addresses["tron"]; ok {
		t.Fatalf("expected tron to be hidden from init payload, got %+v", addresses)
	}
	if payload["existing_identity"] != true {
		t.Fatalf("expected existing_identity flag to be set, got %+v", payload["existing_identity"])
	}
	if payload["locked_reason"] != "locked" {
		t.Fatalf("expected locked_reason to be trimmed, got %+v", payload["locked_reason"])
	}
}

func TestPublicTrackedAddressesOmitDisabledTron(t *testing.T) {
	got := publicTrackedAddresses(map[string]string{
		"ethereum": "0xabc",
		"tron":     "TQzD9a6c3aVb1Q4o6y8P4Ff6dQGmW3qJ7v",
		"solana":   "sol-address",
	})
	if got["ethereum"] != "0xabc" {
		t.Fatalf("expected ethereum to remain visible, got %+v", got)
	}
	if _, ok := got["tron"]; ok {
		t.Fatalf("expected tron to be filtered out, got %+v", got)
	}
	if got["solana"] != "sol-address" {
		t.Fatalf("expected solana to remain visible, got %+v", got)
	}
}

func TestHandleStatusOmitsDisabledTron(t *testing.T) {
	oldMu := mu
	oldPolicyEngine := policyEngine
	oldAddresses := addresses
	oldBoundUID := boundUid
	oldActivated := activated
	oldPinExpiry := pinExpiry
	t.Cleanup(func() {
		mu = oldMu
		policyEngine = oldPolicyEngine
		addresses = oldAddresses
		boundUid = oldBoundUID
		activated = oldActivated
		pinExpiry = oldPinExpiry
	})

	mu = &sync.RWMutex{}
	policyEngine = newTestPolicyEngine(t)
	addresses = map[string]string{
		"ethereum": "0xabc",
		"tron":     "TQzD9a6c3aVb1Q4o6y8P4Ff6dQGmW3qJ7v",
	}
	boundUid = ""
	activated = false
	pinExpiry = time.Time{}

	req := httptest.NewRequest(http.MethodGet, "/api/v1/wallet/status", nil)
	rr := httptest.NewRecorder()
	handleStatus(rr, req)

	if rr.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d body=%s", rr.Code, rr.Body.String())
	}

	var payload struct {
		Addresses        map[string]string `json:"addresses"`
		AddressExplorers map[string]string `json:"address_explorers"`
	}
	if err := json.NewDecoder(rr.Body).Decode(&payload); err != nil {
		t.Fatalf("decode response: %v", err)
	}
	if _, ok := payload.Addresses["tron"]; ok {
		t.Fatalf("expected tron address to be hidden, got %+v", payload.Addresses)
	}
	if _, ok := payload.AddressExplorers["tron"]; ok {
		t.Fatalf("expected tron explorer to be hidden, got %+v", payload.AddressExplorers)
	}
}

func TestHandleWalletHistoryRejectsDisabledTron(t *testing.T) {
	req := httptest.NewRequest(http.MethodGet, "/api/v1/wallet/history?chain=tron", nil)
	rr := httptest.NewRecorder()
	handleWalletHistory(rr, req)

	if rr.Code != http.StatusBadRequest {
		t.Fatalf("expected 400, got %d body=%s", rr.Code, rr.Body.String())
	}
	if body := rr.Body.String(); body == "" || !containsIgnoreCase(body, "disabled") {
		t.Fatalf("expected disabled error, got %q", body)
	}
}

func TestHandleWalletRefreshChainRejectsDisabledTron(t *testing.T) {
	req := httptest.NewRequest(http.MethodPost, "/api/v1/wallet/refresh/chain", strings.NewReader(`{"chain":"tron"}`))
	req.Header.Set("Content-Type", "application/json")
	rr := httptest.NewRecorder()
	handleWalletRefreshChain(rr, req)

	if rr.Code != http.StatusBadRequest {
		t.Fatalf("expected 400, got %d body=%s", rr.Code, rr.Body.String())
	}
	if body := rr.Body.String(); body == "" || !containsIgnoreCase(body, "disabled") {
		t.Fatalf("expected disabled error, got %q", body)
	}
}

func TestHandleRPCProxyRejectsDisabledTron(t *testing.T) {
	req := httptest.NewRequest(http.MethodPost, "/api/rpc/tron", strings.NewReader(`{"jsonrpc":"2.0","id":1,"method":"eth_blockNumber","params":[]}`))
	req.Header.Set("Content-Type", "application/json")
	rr := httptest.NewRecorder()
	handleRPCProxy(rr, req)

	if rr.Code != http.StatusBadRequest {
		t.Fatalf("expected 400, got %d body=%s", rr.Code, rr.Body.String())
	}
	if body := rr.Body.String(); body == "" || !containsIgnoreCase(body, "disabled") {
		t.Fatalf("expected disabled error, got %q", body)
	}
}

func TestHandleTransferRejectsDisabledTron(t *testing.T) {
	req := httptest.NewRequest(http.MethodPost, "/api/v1/tx/transfer", strings.NewReader(`{"chain":"tron","to":"TNPeeaaFB7K9cmo4uQpcU32zGK8G1NYqeL","amount_wei":"1"}`))
	req.Header.Set("Content-Type", "application/json")
	rr := httptest.NewRecorder()
	handleTransfer(rr, req)

	if rr.Code != http.StatusBadRequest {
		t.Fatalf("expected 400, got %d body=%s", rr.Code, rr.Body.String())
	}
	if body := rr.Body.String(); body == "" || !containsIgnoreCase(body, "disabled") {
		t.Fatalf("expected disabled error, got %q", body)
	}
}

func TestHandleBroadcastRejectsDisabledTron(t *testing.T) {
	req := httptest.NewRequest(http.MethodPost, "/api/v1/tx/broadcast", strings.NewReader(`{"chain":"tron","raw_tx_hex":"0x01"}`))
	req.Header.Set("Content-Type", "application/json")
	rr := httptest.NewRecorder()
	handleBroadcast(rr, req)

	if rr.Code != http.StatusBadRequest {
		t.Fatalf("expected 400, got %d body=%s", rr.Code, rr.Body.String())
	}
	if body := rr.Body.String(); body == "" || !containsIgnoreCase(body, "disabled") {
		t.Fatalf("expected disabled error, got %q", body)
	}
}

func containsIgnoreCase(haystack, needle string) bool {
	return strings.Contains(strings.ToLower(haystack), strings.ToLower(needle))
}

func TestBuildUpdatedLocalPolicyRejectsWhitelistUpdates(t *testing.T) {
	current := policy.Policy{}
	_, err := buildUpdatedLocalPolicy(current, localPolicyUpdateRequest{
		WhitelistTo: &[]policy.AddressNote{
			{
				Address: "0xabc",
				Chain:   "ethereum",
				Note:    "allowed",
			},
		},
	})
	if err == nil {
		t.Fatal("expected whitelist update to be rejected")
	}
}

func TestReconcilePINResidencyLockedOnPolicyChangeDoesNotExtendActiveSession(t *testing.T) {
	dir := t.TempDir()
	policyPath := filepath.Join(dir, "policy.json")
	raw, err := json.Marshal(policy.Policy{PinTTLSeconds: 6400})
	if err != nil {
		t.Fatalf("marshal policy: %v", err)
	}
	if err := os.WriteFile(policyPath, raw, 0600); err != nil {
		t.Fatalf("write policy: %v", err)
	}
	engine, err := policy.NewEngine(policyPath)
	if err != nil {
		t.Fatalf("new policy engine: %v", err)
	}

	oldMu := mu
	oldPolicyEngine := policyEngine
	oldActivated := activated
	oldPinExpiry := pinExpiry
	t.Cleanup(func() {
		mu = oldMu
		policyEngine = oldPolicyEngine
		activated = oldActivated
		pinExpiry = oldPinExpiry
	})

	mu = &sync.RWMutex{}
	policyEngine = engine
	activated = true
	pinExpiry = time.Now().Add(5 * time.Minute)
	originalExpiry := pinExpiry

	reconcilePINResidencyLockedOnPolicyChange()

	if pinExpiry.After(originalExpiry.Add(2 * time.Second)) {
		t.Fatalf("expected reconcile to avoid extending ttl, got expiry=%s original=%s", pinExpiry, originalExpiry)
	}
}

func TestReconcilePINResidencyLockedOnPolicyChangeClampsToStricterTTL(t *testing.T) {
	dir := t.TempDir()
	policyPath := filepath.Join(dir, "policy.json")
	raw, err := json.Marshal(policy.Policy{PinTTLSeconds: 120})
	if err != nil {
		t.Fatalf("marshal policy: %v", err)
	}
	if err := os.WriteFile(policyPath, raw, 0600); err != nil {
		t.Fatalf("write policy: %v", err)
	}
	engine, err := policy.NewEngine(policyPath)
	if err != nil {
		t.Fatalf("new policy engine: %v", err)
	}

	oldMu := mu
	oldPolicyEngine := policyEngine
	oldActivated := activated
	oldPinExpiry := pinExpiry
	t.Cleanup(func() {
		mu = oldMu
		policyEngine = oldPolicyEngine
		activated = oldActivated
		pinExpiry = oldPinExpiry
	})

	mu = &sync.RWMutex{}
	policyEngine = engine
	activated = true
	pinExpiry = time.Now().Add(10 * time.Minute)

	reconcilePINResidencyLockedOnPolicyChange()

	remaining := time.Until(pinExpiry)
	if remaining > 122*time.Second || remaining < 110*time.Second {
		t.Fatalf("expected reconcile to clamp ttl near 120s, got remaining=%s", remaining)
	}
}

func TestRPCRequestAllowsFallbackForReadMethodsOnly(t *testing.T) {
	if !rpcRequestAllowsFallback([]byte(`{"jsonrpc":"2.0","id":1,"method":"eth_chainId","params":[]}`)) {
		t.Fatalf("expected read-only eth_chainId to allow fallback")
	}
	if !rpcRequestAllowsFallback([]byte(`{"jsonrpc":"2.0","id":1,"method":"eth_sendRawTransaction","params":["0xabc"]}`)) {
		t.Fatalf("expected eth_sendRawTransaction to allow safe broadcast fallback")
	}
	if rpcRequestAllowsFallback([]byte(`{"jsonrpc":"2.0","id":1,"method":"eth_sendTransaction","params":[{}]}`)) {
		t.Fatalf("expected eth_sendTransaction to disable fallback")
	}
}

func TestDoRPCProxyRequestFallsBackToNextEndpoint(t *testing.T) {
	first := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Error(w, "temporary upstream failure", http.StatusBadGateway)
	}))
	defer first.Close()

	second := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"jsonrpc":"2.0","id":1,"result":"0x38"}`))
	}))
	defer second.Close()

	resp, upstream, err := doRPCProxyRequest([]string{first.URL, second.URL}, []byte(`{"jsonrpc":"2.0","id":1,"method":"eth_chainId","params":[]}`), true)
	if err != nil {
		t.Fatalf("expected fallback request to succeed, got %v", err)
	}
	defer resp.Body.Close()
	if upstream != second.URL {
		t.Fatalf("expected fallback to use second upstream, got %s", upstream)
	}
	body, err := io.ReadAll(resp.Body)
	if err != nil {
		t.Fatalf("failed to read response body: %v", err)
	}
	if string(body) != `{"jsonrpc":"2.0","id":1,"result":"0x38"}` {
		t.Fatalf("unexpected response body: %s", string(body))
	}
}

func TestDoRPCProxyRequestFallsBackOnRetryableJSONRPCError(t *testing.T) {
	first := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"jsonrpc":"2.0","id":1,"error":{"code":-32090,"message":"Too many requests, retry in 10s"}}`))
	}))
	defer first.Close()

	second := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"jsonrpc":"2.0","id":1,"result":"0x38"}`))
	}))
	defer second.Close()

	resp, upstream, err := doRPCProxyRequest([]string{first.URL, second.URL}, []byte(`{"jsonrpc":"2.0","id":1,"method":"eth_getBalance","params":["0xabc","latest"]}`), true)
	if err != nil {
		t.Fatalf("expected retryable JSON-RPC error to fall back, got %v", err)
	}
	defer resp.Body.Close()
	if upstream != second.URL {
		t.Fatalf("expected retryable JSON-RPC error fallback to use second upstream, got %s", upstream)
	}
	body, err := io.ReadAll(resp.Body)
	if err != nil {
		t.Fatalf("failed to read response body: %v", err)
	}
	if string(body) != `{"jsonrpc":"2.0","id":1,"result":"0x38"}` {
		t.Fatalf("unexpected response body after retryable fallback: %s", string(body))
	}
}

func TestDoRPCProxyRequestDoesNotFallbackOnNonRetryableJSONRPCError(t *testing.T) {
	first := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"jsonrpc":"2.0","id":1,"error":{"code":-32602,"message":"invalid params"}}`))
	}))
	defer first.Close()

	second := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		t.Fatalf("non-retryable JSON-RPC error should not hit fallback upstream")
	}))
	defer second.Close()

	resp, upstream, err := doRPCProxyRequest([]string{first.URL, second.URL}, []byte(`{"jsonrpc":"2.0","id":1,"method":"eth_getBalance","params":["bad","latest"]}`), true)
	if err != nil {
		t.Fatalf("expected non-retryable JSON-RPC error to be returned, got %v", err)
	}
	defer resp.Body.Close()
	if upstream != first.URL {
		t.Fatalf("expected non-retryable JSON-RPC error to stay on first upstream, got %s", upstream)
	}
	body, err := io.ReadAll(resp.Body)
	if err != nil {
		t.Fatalf("failed to read response body: %v", err)
	}
	if string(body) != `{"jsonrpc":"2.0","id":1,"error":{"code":-32602,"message":"invalid params"}}` {
		t.Fatalf("unexpected non-retryable response body: %s", string(body))
	}
}
