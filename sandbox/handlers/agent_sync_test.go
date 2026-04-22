package handlers

import (
	"crypto/ecdh"
	"crypto/rand"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	gc "sandbox/internals/crypto"
	"strings"
	"sync"
	"testing"
	"time"

	"sandbox/internals/policy"
)

func TestBuildLocalPolicySyncPayloadForPolicy(t *testing.T) {
	if payload := buildLocalPolicySyncPayloadForPolicy(policy.Policy{}); payload == nil {
		t.Fatalf("expected payload even for default policy sync, got nil")
	}

	payload := buildLocalPolicySyncPayloadForPolicy(policy.Policy{
		MaxAmountPerTxUSD: 50,
		DailyLimitUSD:     500,
		DailyMaxTxCount:   7,
		WhitelistTo: []policy.AddressNote{
			{Address: "0xabc", Chain: "ethereum", Note: "friend"},
		},
		BlacklistTo: []policy.AddressNote{
			{Address: "So111", Chain: "solana", Note: "deny"},
		},
		UnpricedAssetPolicy: "allow",
		AllowBlindSign:      true,
		StrictPlainText:     false,
	})
	if payload == nil {
		t.Fatal("expected local policy sync payload")
	}
	if payload.MaxAmountPerTxUSD != 50 || payload.DailyLimitUSD != 500 || payload.DailyMaxTxCount != 7 {
		t.Fatalf("unexpected numeric payload: %+v", payload)
	}
	if len(payload.WhitelistTo) != 0 {
		t.Fatalf("expected whitelist payload to stay local-only, got %+v", payload.WhitelistTo)
	}
	if len(payload.BlacklistTo) != 1 || payload.BlacklistTo[0].Address != "So111" {
		t.Fatalf("unexpected blacklist payload: %+v", payload.BlacklistTo)
	}
	if payload.UnpricedAssetPolicy != "allow" || !payload.AllowBlindSign || payload.StrictPlainText {
		t.Fatalf("unexpected flag payload: %+v", payload)
	}
}

func TestSyncPendingPolicyBeforeProvisionedUnlockAppliesLatestTTL(t *testing.T) {
	dir := t.TempDir()
	policyPath := filepath.Join(dir, "policy.json")
	initialPolicy, err := json.MarshalIndent(policy.Policy{PinTTLSeconds: 900}, "", "  ")
	if err != nil {
		t.Fatalf("marshal initial policy: %v", err)
	}
	if err := os.WriteFile(policyPath, initialPolicy, 0600); err != nil {
		t.Fatalf("write initial policy: %v", err)
	}

	engine, err := policy.NewEngine(policyPath)
	if err != nil {
		t.Fatalf("new policy engine: %v", err)
	}
	if got := engine.GetTTL(); got != 900 {
		t.Fatalf("expected initial ttl 900, got %d", got)
	}

	oldPolicyPath, hadPolicyPath := os.LookupEnv("POLICY_PATH")
	oldIdentityPath, hadIdentityPath := os.LookupEnv("IDENTITY_PATH")
	oldAgentToken, hadAgentToken := os.LookupEnv("AGENT_TOKEN")
	if err := os.Setenv("POLICY_PATH", policyPath); err != nil {
		t.Fatalf("set POLICY_PATH: %v", err)
	}
	identityPath := filepath.Join(dir, "identity.json")
	agentToken := "test-agent-token"
	sek, err := gc.GenerateSEK()
	if err != nil {
		t.Fatalf("generate sek: %v", err)
	}
	kek := gc.DeriveKEK(agentToken, identityPath)
	wrappedSEK, err := gc.WrapSEK(sek, kek)
	if err != nil {
		t.Fatalf("wrap sek: %v", err)
	}
	identityPayload, err := json.Marshal(map[string]string{
		"wrapped_sek": wrappedSEK,
		"agent_token": agentToken,
	})
	if err != nil {
		t.Fatalf("marshal identity payload: %v", err)
	}
	if err := os.WriteFile(identityPath, identityPayload, 0600); err != nil {
		t.Fatalf("write identity file: %v", err)
	}
	if err := os.Setenv("IDENTITY_PATH", identityPath); err != nil {
		t.Fatalf("set IDENTITY_PATH: %v", err)
	}
	if err := os.Setenv("AGENT_TOKEN", agentToken); err != nil {
		t.Fatalf("set AGENT_TOKEN: %v", err)
	}
	defer func() {
		if hadPolicyPath {
			_ = os.Setenv("POLICY_PATH", oldPolicyPath)
		} else {
			_ = os.Unsetenv("POLICY_PATH")
		}
		if hadIdentityPath {
			_ = os.Setenv("IDENTITY_PATH", oldIdentityPath)
		} else {
			_ = os.Unsetenv("IDENTITY_PATH")
		}
		if hadAgentToken {
			_ = os.Setenv("AGENT_TOKEN", oldAgentToken)
		} else {
			_ = os.Unsetenv("AGENT_TOKEN")
		}
	}()

	oldMu := mu
	oldPolicyEngine := policyEngine
	oldRelayURL := relayURL
	oldActivated := activated
	oldBoundUID := boundUid
	oldMasterPubKey := masterPubKey
	oldRelayPINCache := relayPINCache
	oldLastAgentSync := lastAgentSync
	oldLastPeriodicSyncAt := lastPeriodicSyncAt
	oldLastPeriodicSyncUID := lastPeriodicSyncUID
	defer func() {
		mu = oldMu
		policyEngine = oldPolicyEngine
		relayURL = oldRelayURL
		activated = oldActivated
		boundUid = oldBoundUID
		masterPubKey = oldMasterPubKey
		relayPINCache = oldRelayPINCache
		lastAgentSync = oldLastAgentSync
		lastPeriodicSyncAt = oldLastPeriodicSyncAt
		lastPeriodicSyncUID = oldLastPeriodicSyncUID
	}()

	var (
		completedStatus string
		completedUID    string
	)
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/agent/sync":
			_ = json.NewEncoder(w).Encode(map[string]any{
				"server_time": time.Now().UTC().Format(time.RFC3339),
				"policy": map[string]any{
					"policy_payload": map[string]any{
						"pin_ttl_seconds": 6400,
					},
				},
			})
		case "/agent/policy/complete":
			var body struct {
				UID    string `json:"uid"`
				Status string `json:"status"`
			}
			if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
				t.Fatalf("decode completion body: %v", err)
			}
			completedUID = body.UID
			completedStatus = body.Status
			w.WriteHeader(http.StatusOK)
		default:
			http.NotFound(w, r)
		}
	}))
	defer server.Close()

	mu = &sync.RWMutex{}
	policyEngine = engine
	relayURL = server.URL
	activated = false
	boundUid = "wallet-uid"
	masterPubKey = "master-pub"
	relayPINCache = map[string]string{}
	lastAgentSync = agentSyncEnvelope{}
	lastPeriodicSyncAt = time.Time{}
	lastPeriodicSyncUID = ""

	priv, err := ecdh.P256().GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("generate unlock key: %v", err)
	}
	if err := syncPendingPolicyBeforeProvisionedUnlock(boundUid, priv); err != nil {
		t.Fatalf("sync pending policy before unlock: %v", err)
	}

	if got := policyEngine.GetTTL(); got != 6400 {
		t.Fatalf("expected updated ttl 6400, got %d", got)
	}
	stored, err := policy.ReadStoredPolicyBytes(policyPath)
	if err != nil {
		t.Fatalf("read stored policy: %v", err)
	}
	if !strings.Contains(string(stored), "\"pin_ttl_seconds\": 6400") {
		t.Fatalf("expected stored policy to include ttl 6400, got %s", string(stored))
	}
	if completedUID != boundUid {
		t.Fatalf("expected completion uid %s, got %s", boundUid, completedUID)
	}
	if completedStatus != "applied" {
		t.Fatalf("expected completion status applied, got %s", completedStatus)
	}
}
