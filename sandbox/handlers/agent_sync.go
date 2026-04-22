package handlers

import (
	"bytes"
	"crypto/ecdh"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log"
	"net/http"
	"sandbox/internals/policy"
	"sort"
	"strings"
	"sync"
	"time"
)

// agentSyncEnvelope mirrors POST /agent/sync JSON from the relay.
type agentSyncEnvelope struct {
	ServerTime   string `json:"server_time"`
	EncryptedPIN *struct {
		EncryptedPINHex string `json:"encrypted_pin_hex"`
		NonceHex        string `json:"nonce_hex"`
	} `json:"encrypted_pin"`
	BindChallenge   *bindChallengeSnapshot `json:"bind_challenge"`
	Unlock          json.RawMessage        `json:"unlock"`
	Migration       json.RawMessage        `json:"migration"`
	Restore         json.RawMessage        `json:"restore"`
	SignRequests    json.RawMessage        `json:"sign_requests"`
	Wipe            json.RawMessage        `json:"wipe"`
	Policy          json.RawMessage        `json:"policy"`
	TxApprovals     json.RawMessage        `json:"tx_approvals"` // 待审批的交易记录列表
	LocalPolicySync json.RawMessage        `json:"local_policy_sync"`
}

type bindChallengeSnapshot struct {
	UID            string `json:"uid"`
	UserID         string `json:"user_id"`
	MessageHashHex string `json:"message_hash_hex"`
	ExpiresAt      string `json:"expires_at"`
	CreatedAt      string `json:"created_at"`
}

type agentLocalPolicySyncPayload struct {
	MaxAmountPerTxUSD   float64              `json:"max_amount_per_tx_usd"`
	DailyLimitUSD       float64              `json:"daily_limit_usd"`
	DailyMaxTxCount     int                  `json:"daily_max_tx_count"`
	WhitelistTo         []policy.AddressNote `json:"whitelist_to,omitempty"`
	BlacklistTo         []policy.AddressNote `json:"blacklist_to,omitempty"`
	UnpricedAssetPolicy string               `json:"unpriced_asset_policy"`
	AllowBlindSign      bool                 `json:"allow_blind_sign"`
	StrictPlainText     bool                 `json:"strict_plain_text"`
}

type agentLocalPolicySyncHashAddressNote struct {
	Address string `json:"address"`
	Note    string `json:"note"`
	Chain   string `json:"chain"`
}

type agentLocalPolicySyncHashPayload struct {
	MaxAmountPerTxUSD   float64                               `json:"max_amount_per_tx_usd"`
	DailyLimitUSD       float64                               `json:"daily_limit_usd"`
	DailyMaxTxCount     int                                   `json:"daily_max_tx_count"`
	BlacklistTo         []agentLocalPolicySyncHashAddressNote `json:"blacklist_to"`
	UnpricedAssetPolicy string                                `json:"unpriced_asset_policy"`
	AllowBlindSign      bool                                  `json:"allow_blind_sign"`
	StrictPlainText     bool                                  `json:"strict_plain_text"`
}

var (
	agentSyncMu   sync.RWMutex
	lastAgentSync agentSyncEnvelope

	periodicAgentSyncMu sync.Mutex
	lastPeriodicSyncAt  time.Time
	lastPeriodicSyncUID string

	localPolicySyncStateMu  sync.RWMutex
	lastLocalPolicyPrevHash string
)

func syncRawHasData(raw json.RawMessage) bool {
	if len(raw) == 0 {
		return false
	}
	s := strings.TrimSpace(string(raw))
	return s != "" && s != "null"
}

func normalizeLocalPolicySyncAddressNotes(notes []policy.AddressNote) []policy.AddressNote {
	if len(notes) == 0 {
		return nil
	}
	normalized := make([]policy.AddressNote, 0, len(notes))
	seen := map[string]struct{}{}
	for _, note := range notes {
		address := strings.TrimSpace(note.Address)
		if address == "" {
			continue
		}
		item := policy.AddressNote{
			Address: address,
			Note:    strings.TrimSpace(note.Note),
			Chain:   strings.ToLower(strings.TrimSpace(note.Chain)),
		}
		key := item.Chain + "|" + item.Address + "|" + item.Note
		if _, ok := seen[key]; ok {
			continue
		}
		seen[key] = struct{}{}
		normalized = append(normalized, item)
	}
	sort.Slice(normalized, func(i, j int) bool {
		if normalized[i].Chain != normalized[j].Chain {
			return normalized[i].Chain < normalized[j].Chain
		}
		if normalized[i].Address != normalized[j].Address {
			return normalized[i].Address < normalized[j].Address
		}
		return normalized[i].Note < normalized[j].Note
	})
	return normalized
}

func buildLocalPolicySyncPayloadForPolicy(current policy.Policy) *agentLocalPolicySyncPayload {
	payload := &agentLocalPolicySyncPayload{
		MaxAmountPerTxUSD:   current.MaxAmountPerTxUSD,
		DailyLimitUSD:       current.DailyLimitUSD,
		DailyMaxTxCount:     current.DailyMaxTxCount,
		UnpricedAssetPolicy: strings.ToLower(strings.TrimSpace(current.UnpricedAssetPolicy)),
		AllowBlindSign:      current.AllowBlindSign,
		StrictPlainText:     current.StrictPlainText,
	}
	if len(current.BlacklistTo) > 0 {
		payload.BlacklistTo = normalizeLocalPolicySyncAddressNotes(current.BlacklistTo)
	}
	return payload
}

func hashLocalPolicySyncPayload(payload *agentLocalPolicySyncPayload) (string, error) {
	if payload == nil {
		return "", nil
	}
	blacklist := make([]agentLocalPolicySyncHashAddressNote, 0, len(payload.BlacklistTo))
	for _, note := range payload.BlacklistTo {
		blacklist = append(blacklist, agentLocalPolicySyncHashAddressNote{
			Address: strings.TrimSpace(note.Address),
			Note:    strings.TrimSpace(note.Note),
			Chain:   strings.ToLower(strings.TrimSpace(note.Chain)),
		})
	}
	raw, err := json.Marshal(agentLocalPolicySyncHashPayload{
		MaxAmountPerTxUSD:   payload.MaxAmountPerTxUSD,
		DailyLimitUSD:       payload.DailyLimitUSD,
		DailyMaxTxCount:     payload.DailyMaxTxCount,
		BlacklistTo:         blacklist,
		UnpricedAssetPolicy: strings.ToLower(strings.TrimSpace(payload.UnpricedAssetPolicy)),
		AllowBlindSign:      payload.AllowBlindSign,
		StrictPlainText:     payload.StrictPlainText,
	})
	if err != nil {
		return "", err
	}
	sum := sha256.Sum256(raw)
	return hex.EncodeToString(sum[:]), nil
}

func setLastLocalPolicyPrevHash(hash string) {
	localPolicySyncStateMu.Lock()
	lastLocalPolicyPrevHash = strings.TrimSpace(hash)
	localPolicySyncStateMu.Unlock()
}

func resetLastLocalPolicyPrevHashForPolicy(current policy.Policy) {
	payload := buildLocalPolicySyncPayloadForPolicy(current)
	hash, err := hashLocalPolicySyncPayload(payload)
	if err != nil {
		log.Printf("[claw wallet sandbox] reset local policy hash failed: %v", err)
		return
	}
	setLastLocalPolicyPrevHash(hash)
}

func buildLocalPolicySyncPayload() (*agentLocalPolicySyncPayload, string, string, error) {
	mu.RLock()
	currentPolicyEngine := policyEngine
	mu.RUnlock()
	if currentPolicyEngine == nil {
		return nil, "", "", nil
	}
	payload := buildLocalPolicySyncPayloadForPolicy(currentPolicyEngine.Current())
	currentHash, err := hashLocalPolicySyncPayload(payload)
	if err != nil {
		return nil, "", "", err
	}
	localPolicySyncStateMu.RLock()
	prevHash := strings.TrimSpace(lastLocalPolicyPrevHash)
	localPolicySyncStateMu.RUnlock()
	if prevHash == "" {
		prevHash = currentHash
	}
	return payload, currentHash, prevHash, nil
}

// postAgentSyncForUID POSTs /agent/sync and refreshes the in-memory snapshot.
func postAgentSyncForUID(uid string, priv *ecdh.PrivateKey) error {
	if relayURL == "" {
		return errors.New("RELAY_URL is not configured")
	}
	if priv == nil {
		return errors.New("ephemeral unlock key is unavailable")
	}
	uid = strings.TrimSpace(uid)
	pubHex := hex.EncodeToString(priv.PublicKey().Bytes())
	runtime := sandboxRuntimeMetricsSnapshot()
	localPolicy, localPolicyHash, localPolicyPrevHash, err := buildLocalPolicySyncPayload()
	if err != nil {
		return err
	}
	body, err := json.Marshal(map[string]any{
		"uid":                        uid,
		"public_key_hex":             pubHex,
		"status":                     runtime.Status,
		"sandbox_version":            currentSandboxVersion(),
		"ttl_remaining_seconds":      runtime.TTLRemainingSeconds,
		"ttl_unlimited":              runtime.TTLUnlimited,
		"today_tx_count":             runtime.TodayTxCount,
		"today_spent_usd":            runtime.TodaySpentUSD,
		"local_policy_hash":          localPolicyHash,
		"local_policy_previous_hash": localPolicyPrevHash,
		"local_policy":               localPolicy,
	})
	if err != nil {
		return err
	}
	client := &http.Client{Timeout: 30 * time.Second}
	req, err := http.NewRequest(http.MethodPost, strings.TrimRight(relayURL, "/")+"/agent/sync", bytes.NewReader(body))
	if err != nil {
		return err
	}
	req.Header.Set("Content-Type", "application/json")
	resp, err := client.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	buf, err := io.ReadAll(io.LimitReader(resp.Body, 1<<22))
	if err != nil {
		return err
	}
	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("agent sync HTTP %d: %s", resp.StatusCode, strings.TrimSpace(string(buf)))
	}
	var env agentSyncEnvelope
	if err := json.Unmarshal(buf, &env); err != nil {
		return fmt.Errorf("decode agent sync: %w", err)
	}
	agentSyncMu.Lock()
	lastAgentSync = env
	agentSyncMu.Unlock()
	return nil
}

// postAgentSyncForUIDPeriodic coalesces background sync requests so multiple
// loops do not hammer the relay at the same time.
func postAgentSyncForUIDPeriodic(uid string, priv *ecdh.PrivateKey, minInterval time.Duration) (bool, error) {
	uid = strings.TrimSpace(uid)

	periodicAgentSyncMu.Lock()
	defer periodicAgentSyncMu.Unlock()

	if minInterval > 0 && uid == lastPeriodicSyncUID && !lastPeriodicSyncAt.IsZero() && time.Since(lastPeriodicSyncAt) < minInterval {
		return false, nil
	}

	if err := postAgentSyncForUID(uid, priv); err != nil {
		return false, err
	}

	lastPeriodicSyncAt = time.Now()
	lastPeriodicSyncUID = uid
	return true, nil
}

func agentSyncSnapshot() agentSyncEnvelope {
	agentSyncMu.RLock()
	defer agentSyncMu.RUnlock()
	return lastAgentSync
}

func prefetchRelayPINFromLastSync(uid string, priv *ecdh.PrivateKey) {
	uid = strings.TrimSpace(uid)
	if uid == "" || priv == nil {
		return
	}
	agentSyncMu.RLock()
	pinObj := lastAgentSync.EncryptedPIN
	agentSyncMu.RUnlock()
	if pinObj == nil || pinObj.EncryptedPINHex == "" {
		return
	}
	pin, decErr := decryptRelayPIN(priv, pinObj.EncryptedPINHex, pinObj.NonceHex)
	if decErr != nil || strings.TrimSpace(pin) == "" {
		return
	}
	mu.Lock()
	relayPINCache[uid] = pin
	isActive := activated
	hasProvisionedShare := hasRemoteManagedShareLocked()
	mu.Unlock()
	log.Printf("[claw wallet sandbox] Relay PIN pre-fetched and cached for uid=%s", uid)
	if isActive && hasProvisionedShare {
		pendingAgentUnlockCompleteMu.Lock()
		pendingAgentUnlockCompleteUID = uid
		pendingAgentUnlockCompleteMu.Unlock()
	}
}

func processRemoteWipeFromSnapshot(wipeRaw json.RawMessage, uid string) {
	uid = strings.TrimSpace(uid)
	if uid == "" || !syncRawHasData(wipeRaw) {
		return
	}
	mu.Lock()
	ExpireActiveSessionLocked("remote_wipe")
	mu.Unlock()

	body, _ := json.Marshal(map[string]string{"uid": uid})
	completeResp, postErr := http.Post(relayURL+"/agent/wipe/complete", "application/json", bytes.NewReader(body))
	if postErr == nil && completeResp != nil && completeResp.Body != nil {
		io.Copy(io.Discard, completeResp.Body)
		completeResp.Body.Close()
	}
	log.Printf("[claw wallet sandbox] Remote memory wipe completed for uid=%s", uid)
}

func processRemotePolicySyncFromSnapshot(uid string, policyRaw json.RawMessage) error {
	mu.RLock()
	currentPolicyEngine := policyEngine
	mu.RUnlock()
	if uid == "" || currentPolicyEngine == nil || !syncRawHasData(policyRaw) {
		return nil
	}

	var pending struct {
		PolicyPayload json.RawMessage `json:"policy_payload"`
	}
	if err := json.Unmarshal(policyRaw, &pending); err != nil {
		return err
	}

	nextPolicy, err := validateSandboxPolicyPayload(pending.PolicyPayload)
	if err != nil {
		log.Printf("[claw wallet sandbox] Policy sync translation failed for uid=%s: %v", uid, err)
		submitPolicySyncResult(uid, false, err.Error())
		return err
	}
	currentPolicy := currentPolicyEngine.Current()
	if policiesEqualForSync(currentPolicy, nextPolicy) {
		resetLastLocalPolicyPrevHashForPolicy(currentPolicy)
		submitPolicySyncResult(uid, true, "")
		return nil
	}
	payload, err := json.MarshalIndent(nextPolicy, "", "  ")
	if err != nil {
		log.Printf("[claw wallet sandbox] Policy sync encode failed for uid=%s: %v", uid, err)
		submitPolicySyncResult(uid, false, err.Error())
		return err
	}
	if err := policy.WriteStoredPolicyBytes(env("POLICY_PATH", "policy.json"), payload); err != nil {
		log.Printf("[claw wallet sandbox] Policy sync persist failed for uid=%s: %v", uid, err)
		submitPolicySyncResult(uid, false, err.Error())
		return err
	}
	if err := currentPolicyEngine.Reload(); err != nil {
		log.Printf("[claw wallet sandbox] Policy sync reload failed for uid=%s: %v", uid, err)
		submitPolicySyncResult(uid, false, err.Error())
		return err
	}
	resetLastLocalPolicyPrevHashForPolicy(currentPolicyEngine.Current())
	mu.Lock()
	if activated {
		reconcilePINResidencyLockedOnPolicyChange()
	}
	mu.Unlock()
	submitPolicySyncResult(uid, true, "")
	log.Printf("[claw wallet sandbox] Policy sync applied for uid=%s", uid)
	return nil
}

// syncPendingPolicyBeforeProvisionedUnlock forces a fresh relay sync before a
// remote-managed wallet transitions back to active so unlock never reuses a
// stale local policy.json while a newer backend policy is still pending.
func syncPendingPolicyBeforeProvisionedUnlock(uid string, priv *ecdh.PrivateKey) error {
	uid = strings.TrimSpace(uid)
	if uid == "" || priv == nil {
		return nil
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

var (
	bindChallengeMu       sync.Mutex
	lastCompletedBindHash string
	lastInFlightBindHash  string
)

func processRemoteBindFromSnapshot(uid string, bindRaw *bindChallengeSnapshot) {
	if bindRaw == nil {
		return
	}
	hashHex := strings.TrimSpace(bindRaw.MessageHashHex)
	if hashHex == "" {
		return
	}

	bindChallengeMu.Lock()
	if hashHex == lastCompletedBindHash || hashHex == lastInFlightBindHash {
		bindChallengeMu.Unlock()
		return
	}
	lastInFlightBindHash = hashHex
	bindChallengeMu.Unlock()

	defer func() {
		bindChallengeMu.Lock()
		if lastInFlightBindHash == hashHex {
			lastInFlightBindHash = ""
		}
		bindChallengeMu.Unlock()
	}()

	respBody, err := submitWalletBindFromChallenge(hashHex)
	if err != nil {
		log.Printf("[claw wallet sandbox] Auto bind failed for uid=%s hash=%s: %v", uid, hashHex, err)
		return
	}

	bindChallengeMu.Lock()
	lastCompletedBindHash = hashHex
	lastInFlightBindHash = ""
	bindChallengeMu.Unlock()
	log.Printf("[claw wallet sandbox] Auto bind completed for uid=%s hash=%s response=%s", uid, hashHex, strings.TrimSpace(string(respBody)))
}
