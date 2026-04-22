package handlers

import (
	"bytes"
	"crypto/ecdh"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log"
	"net/http"
	"os"
	"sandbox/internals/signer"
	"sandbox/internals/utils"
	"strings"
	"sync"
	"time"

	"github.com/joho/godotenv"
)

const (
	// Heartbeats keep relay state fresh while the sandbox is active.
	// Retry loops keep using a shorter cadence so bind / restore / unlock
	// can still react quickly once backend state changes.
	agentSyncHeartbeatInterval = 11 * time.Second
	agentSyncRetryInterval     = 5 * time.Second
)

// 交易审批相关
type syncedTxApproval struct {
	ApprovalID    string `json:"approval_id"`
	UID           string `json:"uid"`
	Status        string `json:"status"`
	Chain         string `json:"chain"`
	SignMode      string `json:"sign_mode"`
	ReasonCode    string `json:"reason_code"`
	Reason        string `json:"reason"`
	IntentHash    string `json:"intent_hash"`
	IntentPayload string `json:"intent_payload"`
}

// 待审批的交易记录列表
type pendingTxApprovalCompletion struct {
	ApprovalID     string
	ExecutionToken string
	Status         string
	ResultPayload  json.RawMessage
	ErrorText      string
}

type share2IntentPayload struct {
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
}

var (
	pendingTxApprovalCompletionMu sync.Mutex
	pendingTxApprovalCompletions  = map[string]pendingTxApprovalCompletion{}
)

func ActivationLoop() {
	for {
		mu.RLock()
		isActive := activated
		uid := strings.TrimSpace(boundUid)
		mPubKey := masterPubKey
		hasRemoteManagedShare := hasRemoteManagedShareLocked()
		currentPriv := ephemeralPriv
		mu.RUnlock()

		if mPubKey == "" {
			time.Sleep(2 * time.Second)
			continue
		}
		if hasRemoteManagedShare {
			time.Sleep(2 * time.Second)
			continue
		}
		if isActive {
			if posted, err := postAgentSyncForUIDPeriodic(uid, currentPriv, agentSyncHeartbeatInterval); err != nil {
				log.Printf("[claw wallet sandbox] activation heartbeat failed: %v", err)
			} else if posted {
				prefetchRelayPINFromLastSync(uid, currentPriv)
			}
			time.Sleep(agentSyncHeartbeatInterval)
			continue
		}

		curve := ecdh.P256()
		priv, _ := curve.GenerateKey(rand.Reader)
		mu.Lock()
		ephemeralPriv = priv
		mu.Unlock()

		// Determine share decryption PIN:
		// Priority 1: use in-memory SEK (set on init or restarted with identity.json containing wrapped_sek)
		// Priority 2: fall back to activateViaRelay (user-injected PIN over E2EE channel)
		mu.RLock()
		currentSEK := sekKey
		mu.RUnlock()

		var sharePIN string
		var err error
		if len(currentSEK) > 0 {
			sharePIN = hex.EncodeToString(currentSEK)
			// Publish ephemeral pub key so Cloud Relay can encrypt Share2 for us
			if err := publishSandboxConnect(uid, priv); err != nil {
				log.Printf("[claw wallet sandbox] activation heartbeat failed: %v", err)
			}
		} else if agentToken := env("AGENT_TOKEN", ""); agentToken != "" {
			// Legacy fallback: if no SEK in memory, try relay-based activation
			if err := publishSandboxConnect(uid, priv); err != nil {
				log.Printf("[claw wallet sandbox] activation heartbeat failed: %v", err)
			}
			// PIN will need to come via relay (activateViaRelay)
			sharePIN, err = activateViaRelay(priv)
		} else {
			sharePIN, err = activateViaRelay(priv)
		}

		if err == nil && sharePIN != "" {
			s, err := signer.New(encShare3, sharePIN, priv, mPubKey)
			if err == nil {
				mu.Lock()
				activeSigner = s
				activated = true
				lockedReason = ""
				applyPINResidencyLocked()
				mu.Unlock()
				log.Println("[claw wallet sandbox] Activated and bound to master public key")
			} else {
				mu.Lock()
				lockedReason = "activation_failed"
				mu.Unlock()
				log.Printf("[claw wallet sandbox] Activation failed (signer.New): %v", err)
			}
		}
		time.Sleep(5 * time.Second)
	}
}

func ProvisionedUnlockLoop() {
	const (
		localStatePollInterval   = 2 * time.Second
		backendIdlePollInterval  = 15 * time.Second
		backendRetryPollInterval = 5 * time.Second
	)
	for {
		mu.RLock()
		isActive := activated
		uid := strings.TrimSpace(boundUid)
		hasRemoteManagedShare := hasRemoteManagedShareLocked()
		currentPriv := ephemeralPriv
		mPubKey := masterPubKey
		mu.RUnlock()

		pendingAgentUnlockCompleteMu.Lock()
		pendingComplete := pendingAgentUnlockCompleteUID
		pendingAgentUnlockCompleteMu.Unlock()
		if pendingComplete != "" && strings.EqualFold(strings.TrimSpace(pendingComplete), uid) &&
			isActive && hasRemoteManagedShare && mPubKey != "" {
			if err := postAgentUnlockComplete(pendingComplete); err != nil {
				log.Printf("[claw wallet sandbox] retry pending unlock complete uid=%s err=%v", pendingComplete, err)
				time.Sleep(backendRetryPollInterval)
				continue
			}
			pendingAgentUnlockCompleteMu.Lock()
			if pendingAgentUnlockCompleteUID == pendingComplete {
				pendingAgentUnlockCompleteUID = ""
			}
			pendingAgentUnlockCompleteMu.Unlock()
			log.Printf("[claw wallet sandbox] pending unlock complete succeeded uid=%s", pendingComplete)
		}

		if isActive {
			if posted, err := postAgentSyncForUIDPeriodic(uid, currentPriv, agentSyncHeartbeatInterval); err != nil {
				log.Printf("[claw wallet sandbox] unlock heartbeat failed uid=%s err=%v", uid, err)
			} else if posted {
				prefetchRelayPINFromLastSync(uid, currentPriv)
			}
			time.Sleep(agentSyncHeartbeatInterval)
			continue
		}

		if mPubKey == "" || uid == "" || isActive || !hasRemoteManagedShare {
			time.Sleep(localStatePollInterval)
			continue
		}

		snap := agentSyncSnapshot()
		if !syncRawHasData(snap.Unlock) {
			time.Sleep(backendIdlePollInterval)
			continue
		}

		var unlockState struct {
			Status                string `json:"status"`
			NeedsAddressesSync    bool   `json:"needs_addresses_sync"`
			AddressesSyncEndpoint string `json:"addresses_sync_endpoint"`
		}
		if err := json.Unmarshal(snap.Unlock, &unlockState); err != nil {
			time.Sleep(backendRetryPollInterval)
			continue
		}

		if unlockState.NeedsAddressesSync {
			if err := syncWalletAddressesToRelay(uid); err != nil {
				log.Printf("[claw wallet sandbox] address sync (unlock loop) failed uid=%s err=%v", uid, err)
			} else {
				log.Printf("[claw wallet sandbox] address sync (unlock loop) done uid=%s", uid)
			}
		}

		priv := currentPriv
		if priv == nil {
			curve := ecdh.P256()
			var genErr error
			priv, genErr = curve.GenerateKey(rand.Reader)
			if genErr != nil {
				time.Sleep(backendRetryPollInterval)
				continue
			}
			mu.Lock()
			if ephemeralPriv == nil {
				ephemeralPriv = priv
			} else {
				priv = ephemeralPriv
			}
			mu.Unlock()
		}

		if unlockState.Status != "pin_delivered" {
			if err := publishSandboxConnect(uid, priv); err != nil {
				time.Sleep(backendRetryPollInterval)
				continue
			}
			time.Sleep(backendIdlePollInterval)
			continue
		}

		pin, ok, fromCache, err := consumeRelayPIN(uid, priv)
		if err != nil || !ok || strings.TrimSpace(pin) == "" {
			if err != nil {
				log.Printf("[claw wallet sandbox] unlock consume PIN error uid=%s err=%v", uid, err)
			} else if !ok {
				log.Printf("[claw wallet sandbox] unlock consume PIN waiting uid=%s", uid)
			}
			time.Sleep(backendRetryPollInterval)
			continue
		}

		if err := syncPendingPolicyBeforeProvisionedUnlock(uid, priv); err != nil {
			log.Printf("[claw wallet sandbox] pre-unlock policy sync failed uid=%s err=%v", uid, err)
			if fromCache {
				restoreRelayPINCache(uid, pin)
			}
			time.Sleep(backendRetryPollInterval)
			continue
		}

		mu.Lock()
		activateErr := activateProvisionedWithPrivLocked(pin, priv)
		mu.Unlock()
		if activateErr != nil {
			log.Printf("[claw wallet sandbox] Provisioned remote unlock failed: %v", activateErr)
			if fromCache {
				restoreRelayPINCache(uid, pin)
			}
			time.Sleep(backendRetryPollInterval)
			continue
		}

		if err := postAgentUnlockComplete(uid); err != nil {
			log.Printf("[claw wallet sandbox] unlock complete failed uid=%s err=%v (wallet may be active locally; relay still pin_delivered)", uid, err)
			pendingAgentUnlockCompleteMu.Lock()
			pendingAgentUnlockCompleteUID = uid
			pendingAgentUnlockCompleteMu.Unlock()
			time.Sleep(backendRetryPollInterval)
			continue
		}
		pendingAgentUnlockCompleteMu.Lock()
		pendingAgentUnlockCompleteUID = ""
		pendingAgentUnlockCompleteMu.Unlock()
		log.Printf("[claw wallet sandbox] Provisioned wallet remote unlock completed for uid=%s", uid)
		time.Sleep(backendIdlePollInterval)
	}
}

func LocalMigrationLoop() {
	const (
		localStatePollInterval   = 2 * time.Second
		backendIdlePollInterval  = 15 * time.Second
		backendRetryPollInterval = 5 * time.Second
	)
	for {
		mu.RLock()
		uid := strings.TrimSpace(boundUid)
		hasRemoteManagedShare := hasRemoteManagedShareLocked()
		hasLocalShare3 := hasLegacyLocalShareLocked()
		currentEncShare3 := encShare3
		mPubKey := masterPubKey
		currentPriv := ephemeralPriv
		currentSEK := append([]byte(nil), sekKey...)
		mu.RUnlock()

		if mPubKey == "" || uid == "" || hasRemoteManagedShare || !hasLocalShare3 || len(currentSEK) == 0 {
			time.Sleep(localStatePollInterval)
			continue
		}

		snap := agentSyncSnapshot()
		if !syncRawHasData(snap.Migration) {
			time.Sleep(backendIdlePollInterval)
			continue
		}

		var migrationState struct {
			Status                string `json:"status"`
			NeedsAddressesSync    bool   `json:"needs_addresses_sync"`
			AddressesSyncEndpoint string `json:"addresses_sync_endpoint"`
		}
		if err := json.Unmarshal(snap.Migration, &migrationState); err != nil {
			time.Sleep(backendRetryPollInterval)
			continue
		}

		if migrationState.NeedsAddressesSync {
			if err := syncWalletAddressesToRelay(uid); err != nil {
				log.Printf("[claw wallet sandbox] address sync (migration loop) failed uid=%s err=%v", uid, err)
			} else {
				log.Printf("[claw wallet sandbox] address sync (migration loop) done uid=%s", uid)
			}
		}

		priv := currentPriv
		if priv == nil {
			curve := ecdh.P256()
			var genErr error
			priv, genErr = curve.GenerateKey(rand.Reader)
			if genErr != nil {
				time.Sleep(backendRetryPollInterval)
				continue
			}
			mu.Lock()
			if ephemeralPriv == nil {
				ephemeralPriv = priv
			} else {
				priv = ephemeralPriv
			}
			mu.Unlock()
		}

		switch strings.ToLower(strings.TrimSpace(migrationState.Status)) {
		case "pin_delivered":
			log.Printf("[claw wallet sandbox] Local migration status=pin_delivered uid=%s", uid)
			// Continue below to consume PIN.
		case "pending":
			log.Printf("[claw wallet sandbox] Local migration status=pending uid=%s", uid)
			if err := publishSandboxConnect(uid, priv); err != nil {
				time.Sleep(backendRetryPollInterval)
				continue
			}
			time.Sleep(backendIdlePollInterval)
			continue
		case "not_found", "expired", "completed":
			time.Sleep(backendIdlePollInterval)
			continue
		default:
			log.Printf("[claw wallet sandbox] Local migration status=%s uid=%s (unexpected)", strings.ToLower(strings.TrimSpace(migrationState.Status)), uid)
			time.Sleep(backendRetryPollInterval)
			continue
		}

		pin, ok, fromCache, err := consumeRelayPIN(uid, priv)
		if err != nil || !ok || strings.TrimSpace(pin) == "" {
			if err != nil {
				log.Printf("[claw wallet sandbox] Local migration consume PIN failed uid=%s err=%v", uid, err)
			} else {
				log.Printf("[claw wallet sandbox] Local migration consume PIN waiting uid=%s", uid)
			}
			time.Sleep(backendRetryPollInterval)
			continue
		}

		sharePIN := hex.EncodeToString(currentSEK)
		tempSigner, err := signer.New(currentEncShare3, sharePIN, priv, mPubKey)
		if err != nil {
			if fromCache {
				restoreRelayPINCache(uid, pin)
			}
			log.Printf("[claw wallet sandbox] Local migration signer setup failed: %v", err)
			time.Sleep(backendRetryPollInterval)
			continue
		}
		wrappedShare2, share2Nonce, err := fetchWrappedShare2ForUID(uid)
		if err != nil {
			tempSigner.Wipe()
			if fromCache {
				restoreRelayPINCache(uid, pin)
			}
			log.Printf("[claw wallet sandbox] Local migration share2 fetch failed: %v", err)
			time.Sleep(backendRetryPollInterval)
			continue
		}
		reshard, err := tempSigner.ReshardLocalToPIN(pin, wrappedShare2, share2Nonce)
		tempSigner.Wipe()
		if err != nil {
			if fromCache {
				restoreRelayPINCache(uid, pin)
			}
			log.Printf("[claw wallet sandbox] Local migration re-shard failed: %v", err)
			time.Sleep(backendRetryPollInterval)
			continue
		}

		body, _ := json.Marshal(map[string]any{
			"uid":        uid,
			"enc_share1": reshard.Share1,
			"enc_share2": reshard.Share2,
			"enc_share3": reshard.Share3,
		})
		completeResp, err := http.Post(relayURL+"/agent/migration/complete", "application/json", bytes.NewReader(body))
		if err != nil {
			if fromCache {
				restoreRelayPINCache(uid, pin)
			}
			log.Printf("[claw wallet sandbox] Local migration completion submit failed: %v", err)
			time.Sleep(backendRetryPollInterval)
			continue
		}
		if completeResp != nil && completeResp.Body != nil {
			io.Copy(io.Discard, completeResp.Body)
			completeResp.Body.Close()
		}
		if completeResp == nil || completeResp.StatusCode != http.StatusOK {
			if fromCache {
				restoreRelayPINCache(uid, pin)
			}
			log.Printf("[claw wallet sandbox] Local migration completion rejected for uid=%s", uid)
			time.Sleep(backendRetryPollInterval)
			continue
		}

		mu.Lock()
		persistErr := persistMigratedRemoteWalletLocked(reshard.Share3)
		mu.Unlock()
		if persistErr == nil {
			if err := syncPendingPolicyBeforeProvisionedUnlock(uid, priv); err != nil {
				persistErr = err
			} else {
				mu.Lock()
				persistErr = activateProvisionedWithPrivLocked(pin, priv)
				mu.Unlock()
			}
		}
		if persistErr != nil {
			if fromCache {
				restoreRelayPINCache(uid, pin)
			}
			log.Printf("[claw wallet sandbox] Local migration state switch failed: %v", persistErr)
			time.Sleep(backendRetryPollInterval)
			continue
		}

		log.Printf("[claw wallet sandbox] Local wallet migration completed for uid=%s", uid)
		time.Sleep(backendIdlePollInterval)
	}
}

func RestoreLoop() {
	const (
		localStatePollInterval   = 2 * time.Second
		backendIdlePollInterval  = 15 * time.Second
		backendRetryPollInterval = 5 * time.Second
	)
	for {
		mu.RLock()
		uid := strings.TrimSpace(boundUid)
		mPubKey := strings.TrimSpace(masterPubKey)
		hasProvisionedShare1 := encShare1.Cipher != ""
		hasLocalShare3 := encShare3.Cipher != ""
		isActive := activated
		currentPriv := ephemeralPriv
		mu.RUnlock()

		if isActive || uid != "" || mPubKey != "" || hasProvisionedShare1 || hasLocalShare3 {
			time.Sleep(localStatePollInterval)
			continue
		}

		priv := currentPriv
		if priv == nil {
			curve := ecdh.P256()
			var genErr error
			priv, genErr = curve.GenerateKey(rand.Reader)
			if genErr != nil {
				time.Sleep(backendRetryPollInterval)
				continue
			}
			mu.Lock()
			if ephemeralPriv == nil {
				ephemeralPriv = priv
			} else {
				priv = ephemeralPriv
			}
			mu.Unlock()
		}
		if err := postAgentSyncForUID("", priv); err != nil {
			time.Sleep(backendRetryPollInterval)
			continue
		}

		snap := agentSyncSnapshot()
		if !syncRawHasData(snap.Restore) {
			time.Sleep(backendIdlePollInterval)
			continue
		}

		var restoreState struct {
			UID           string `json:"uid"`
			Status        string `json:"status"`
			BackupPackage struct {
				UID          string                `json:"uid"`
				MasterPubKey string                `json:"master_pub_key"`
				Addresses    map[string]string     `json:"addresses"`
				EncShare1    signer.EncryptedShare `json:"enc_share1"`
			} `json:"backup_package"`
		}
		if err := json.Unmarshal(snap.Restore, &restoreState); err != nil {
			time.Sleep(backendRetryPollInterval)
			continue
		}
		if strings.TrimSpace(restoreState.UID) == "" ||
			strings.TrimSpace(restoreState.BackupPackage.UID) == "" ||
			strings.TrimSpace(restoreState.BackupPackage.MasterPubKey) == "" ||
			restoreState.BackupPackage.EncShare1.Cipher == "" {
			log.Printf("[claw wallet sandbox] Restore request is missing required backup material")
			time.Sleep(backendRetryPollInterval)
			continue
		}

		if restoreState.Status != "pin_delivered" {
			if err := publishSandboxConnect(restoreState.UID, priv); err != nil {
				time.Sleep(backendRetryPollInterval)
				continue
			}
			time.Sleep(backendIdlePollInterval)
			continue
		}

		pin, ok, fromCache, err := consumeRelayPIN(restoreState.UID, priv)
		if err != nil || !ok || strings.TrimSpace(pin) == "" {
			time.Sleep(backendRetryPollInterval)
			continue
		}

		tempSigner, err := signer.NewProvisioned(
			restoreState.BackupPackage.EncShare1,
			pin,
			priv,
			restoreState.BackupPackage.MasterPubKey,
		)
		if err != nil {
			if fromCache {
				restoreRelayPINCache(restoreState.UID, pin)
			}
			log.Printf("[claw wallet sandbox] Restore signer setup failed: %v", err)
			time.Sleep(backendRetryPollInterval)
			continue
		}

		wrappedShare2, share2Nonce, err := fetchWrappedShare2ForUID(restoreState.UID)
		if err != nil {
			tempSigner.Wipe()
			if fromCache {
				restoreRelayPINCache(restoreState.UID, pin)
			}
			log.Printf("[claw wallet sandbox] Restore share2 fetch failed: %v", err)
			time.Sleep(backendRetryPollInterval)
			continue
		}

		reshard, err := tempSigner.ReshardProvisionedToPIN(pin, wrappedShare2, share2Nonce)
		tempSigner.Wipe()
		if err != nil {
			if fromCache {
				restoreRelayPINCache(restoreState.UID, pin)
			}
			log.Printf("[claw wallet sandbox] Restore re-shard failed: %v", err)
			time.Sleep(backendRetryPollInterval)
			continue
		}

		body, _ := json.Marshal(map[string]any{
			"uid":        restoreState.UID,
			"enc_share1": reshard.Share1,
			"enc_share2": reshard.Share2,
			"enc_share3": reshard.Share3,
		})
		completeResp, err := http.Post(relayURL+"/agent/restore/complete", "application/json", bytes.NewReader(body))
		if err != nil {
			if fromCache {
				restoreRelayPINCache(restoreState.UID, pin)
			}
			log.Printf("[claw wallet sandbox] Restore completion submit failed: %v", err)
			time.Sleep(backendRetryPollInterval)
			continue
		}
		if completeResp != nil && completeResp.Body != nil {
			io.Copy(io.Discard, completeResp.Body)
			completeResp.Body.Close()
		}
		if completeResp == nil || completeResp.StatusCode != http.StatusOK {
			if fromCache {
				restoreRelayPINCache(restoreState.UID, pin)
			}
			log.Printf("[claw wallet sandbox] Restore completion rejected for uid=%s", restoreState.UID)
			time.Sleep(backendRetryPollInterval)
			continue
		}

		mu.Lock()
		persistErr := importProvisionedWalletLocked(
			restoreState.UID,
			restoreState.BackupPackage.MasterPubKey,
			restoreState.BackupPackage.Addresses,
			reshard.Share3,
		)
		mu.Unlock()
		if persistErr == nil {
			if err := syncPendingPolicyBeforeProvisionedUnlock(restoreState.UID, priv); err != nil {
				persistErr = err
			} else {
				mu.Lock()
				persistErr = activateProvisionedWithPrivLocked(pin, priv)
				mu.Unlock()
			}
		}
		if persistErr != nil {
			if fromCache {
				restoreRelayPINCache(restoreState.UID, pin)
			}
			log.Printf("[claw wallet sandbox] Restore state switch failed: %v", persistErr)
			time.Sleep(backendRetryPollInterval)
			continue
		}

		log.Printf("[claw wallet sandbox] Remote wallet restore completed for uid=%s", restoreState.UID)
		time.Sleep(backendIdlePollInterval)
	}
}

func SignSessionLoop() {
	const (
		localStatePollInterval   = 2 * time.Second
		backendIdlePollInterval  = 15 * time.Second
		backendRetryPollInterval = 5 * time.Second
	)
	for {
		mu.RLock()
		uid := strings.TrimSpace(boundUid)
		mPubKey := masterPubKey
		hasRemoteManagedShare := hasRemoteManagedShareLocked()
		currentPriv := ephemeralPriv
		isActive := activated
		mu.RUnlock()

		if mPubKey == "" || uid == "" || !hasRemoteManagedShare {
			time.Sleep(localStatePollInterval)
			continue
		}

		snap := agentSyncSnapshot()
		if !syncRawHasData(snap.SignRequests) {
			time.Sleep(backendIdlePollInterval)
			continue
		}

		var signRequests []struct {
			SignID         string          `json:"sign_id"`
			UID            string          `json:"uid"`
			Status         string          `json:"status"`
			RequestPayload json.RawMessage `json:"request_payload"`
		}
		if err := json.Unmarshal(snap.SignRequests, &signRequests); err != nil {
			time.Sleep(backendRetryPollInterval)
			continue
		}
		if len(signRequests) == 0 {
			time.Sleep(backendIdlePollInterval)
			continue
		}

		req := signRequests[0]
		priv := currentPriv
		if priv == nil {
			curve := ecdh.P256()
			var genErr error
			priv, genErr = curve.GenerateKey(rand.Reader)
			if genErr != nil {
				time.Sleep(backendRetryPollInterval)
				continue
			}
			mu.Lock()
			if ephemeralPriv == nil {
				ephemeralPriv = priv
			} else {
				priv = ephemeralPriv
			}
			mu.Unlock()
		}

		if !isActive && req.Status != "pin_delivered" {
			if err := publishSandboxConnect(req.UID, priv); err != nil {
				time.Sleep(backendRetryPollInterval)
				continue
			}
			time.Sleep(backendIdlePollInterval)
			continue
		}

		if !isActive && req.Status == "pin_delivered" {
			pin, ok, fromCache, err := consumeRelayPIN(req.UID, priv)
			if err != nil || !ok || strings.TrimSpace(pin) == "" {
				time.Sleep(backendRetryPollInterval)
				continue
			}

			if err := syncPendingPolicyBeforeProvisionedUnlock(req.UID, priv); err != nil {
				if fromCache {
					restoreRelayPINCache(req.UID, pin)
				}
				submitSignSessionResult(req.SignID, false, nil, "failed to sync latest wallet policy before activation: "+err.Error())
				time.Sleep(backendRetryPollInterval)
				continue
			}

			mu.Lock()
			activateErr := activateProvisionedWithPrivLocked(pin, priv)
			mu.Unlock()
			if activateErr != nil {
				if fromCache {
					restoreRelayPINCache(req.UID, pin)
				}
				submitSignSessionResult(req.SignID, false, nil, activateErr.Error())
				time.Sleep(backendRetryPollInterval)
				continue
			}
		}

		resultPayload, execErr := executeSignSessionPayload(req.RequestPayload)
		if execErr != nil {
			submitSignSessionResult(req.SignID, false, nil, execErr.Error())
			time.Sleep(backendRetryPollInterval)
			continue
		}
		submitSignSessionResult(req.SignID, true, resultPayload, "")
		log.Printf("[claw wallet sandbox] Sign session completed for uid=%s sign_id=%s", req.UID, req.SignID)
		time.Sleep(localStatePollInterval)
	}
}

// 查询待审批的交易记录列表，并执行已批准的交易
func queuePendingTxApprovalCompletion(result pendingTxApprovalCompletion) {
	if strings.TrimSpace(result.ApprovalID) == "" || strings.TrimSpace(result.ExecutionToken) == "" {
		return
	}
	pendingTxApprovalCompletionMu.Lock()
	pendingTxApprovalCompletions[result.ApprovalID] = result
	pendingTxApprovalCompletionMu.Unlock()
}

// 处理待审批的交易记录列表，向 Cloud Relay 汇报执行结果，并从列表中移除已处理的记录
func flushPendingTxApprovalCompletions() {
	if relayURL == "" {
		return
	}
	pendingTxApprovalCompletionMu.Lock()
	items := make([]pendingTxApprovalCompletion, 0, len(pendingTxApprovalCompletions))
	for _, item := range pendingTxApprovalCompletions {
		items = append(items, item)
	}
	pendingTxApprovalCompletionMu.Unlock()

	for _, item := range items {
		body, _ := json.Marshal(map[string]any{
			"approval_id":     item.ApprovalID,
			"execution_token": item.ExecutionToken,
			"status":          item.Status,
			"result_payload":  item.ResultPayload,
			"error":           item.ErrorText,
		})
		resp, err := http.Post(relayURL+"/agent/tx-approval/complete", "application/json", bytes.NewReader(body))
		if err != nil {
			log.Printf("[claw wallet sandbox] tx approval complete POST error approval_id=%s err=%v", item.ApprovalID, err)
			continue
		}
		respBody, _ := io.ReadAll(io.LimitReader(resp.Body, 4096))
		resp.Body.Close()
		if resp.StatusCode < 200 || resp.StatusCode >= 300 {
			log.Printf("[claw wallet sandbox] tx approval complete rejected approval_id=%s status=%d body=%s", item.ApprovalID, resp.StatusCode, strings.TrimSpace(string(respBody)))
			continue
		}
		pendingTxApprovalCompletionMu.Lock()
		delete(pendingTxApprovalCompletions, item.ApprovalID)
		pendingTxApprovalCompletionMu.Unlock()
	}
}

func parseShare2IntentPayload(task syncedTxApproval) (share2IntentPayload, error) {
	var intent share2IntentPayload
	if err := json.Unmarshal([]byte(strings.TrimSpace(task.IntentPayload)), &intent); err != nil {
		return share2IntentPayload{}, fmt.Errorf("invalid intent payload: %w", err)
	}
	if strings.TrimSpace(intent.UID) == "" {
		intent.UID = strings.TrimSpace(task.UID)
	}
	if strings.TrimSpace(intent.Chain) == "" {
		intent.Chain = strings.TrimSpace(task.Chain)
	}
	return intent, nil
}

func intentCanReplayAsTransfer(intent share2IntentPayload) bool {
	mode := strings.ToLower(strings.TrimSpace(intent.SignMode))
	if mode != "" && mode != "transaction" {
		return false
	}
	chain := strings.ToLower(strings.TrimSpace(intent.Chain))
	if strings.TrimSpace(intent.To) == "" || strings.TrimSpace(intent.AmountWei) == "" || chain == "" {
		return false
	}
	if strings.TrimSpace(intent.TxPayloadHex) != "" || strings.TrimSpace(intent.Data) != "" || len(intent.TypedData) > 0 {
		return false
	}
	builderKind := strings.TrimSpace(intent.BuilderKind)
	if builderKind != "" {
		return builderKind == "native_transfer" || builderKind == "erc20_transfer"
	}
	if signer.IsEVMChain(chain) {
		return false
	}
	return true
}

func buildTransferRequestFromIntent(intent share2IntentPayload, approvalID, executionToken string) (*TransferRequest, error) {
	chain := strings.ToLower(strings.TrimSpace(intent.Chain))
	to := strings.TrimSpace(intent.To)
	amountWei := strings.TrimSpace(intent.AmountWei)
	if chain == "" || to == "" || amountWei == "" {
		return nil, errors.New("intent payload is missing transfer fields")
	}
	return &TransferRequest{
		UID:            strings.TrimSpace(intent.UID),
		Chain:          chain,
		To:             to,
		AmountWei:      amountWei,
		TokenContract:  strings.TrimSpace(intent.TokenContract),
		ApprovalID:     strings.TrimSpace(approvalID),
		ExecutionToken: strings.TrimSpace(executionToken),
	}, nil
}

func buildSignRequestFromIntent(intent share2IntentPayload, approvalID, executionToken string) *signer.SignRequest {
	return &signer.SignRequest{
		Chain:          strings.ToLower(strings.TrimSpace(intent.Chain)),
		SignMode:       strings.TrimSpace(intent.SignMode),
		DerivationPath: strings.TrimSpace(intent.DerivationPath),
		BuilderKind:    strings.TrimSpace(intent.BuilderKind),
		To:             strings.TrimSpace(intent.To),
		TokenContract:  strings.TrimSpace(intent.TokenContract),
		AmountWei:      strings.TrimSpace(intent.AmountWei),
		Data:           strings.TrimSpace(intent.Data),
		UID:            strings.TrimSpace(intent.UID),
		IsUserApproval: true,
		ApprovalID:     strings.TrimSpace(approvalID),
		ExecutionToken: strings.TrimSpace(executionToken),
		TxPayloadHex:   strings.TrimSpace(intent.TxPayloadHex),
		TypedData:      intent.TypedData,
	}
}

// 执行已批准的交易记录，并返回执行结果
func ExecuteApprovedTxApproval(task syncedTxApproval, executionToken string) pendingTxApprovalCompletion {
	result := pendingTxApprovalCompletion{
		ApprovalID:     strings.TrimSpace(task.ApprovalID),
		ExecutionToken: strings.TrimSpace(executionToken),
		Status:         "execution_failed",
	}
	intent, err := parseShare2IntentPayload(task)
	if err != nil {
		result.ErrorText = err.Error()
		return result
	}
	// 需要区分是转账还是签名交易
	if intentCanReplayAsTransfer(intent) {
		req, err := buildTransferRequestFromIntent(intent, task.ApprovalID, executionToken)
		if err != nil {
			result.ErrorText = err.Error()
			return result
		}
		respBody, err := callLocalAPI(http.MethodPost, "/api/v1/tx/transfer", req)
		if err != nil {
			result.ErrorText = err.Error()
			return result
		}
		result.Status = "submitted"
		result.ResultPayload = json.RawMessage(respBody)
		return result
	}

	signReq := buildSignRequestFromIntent(intent, task.ApprovalID, executionToken)
	respBody, err := callLocalAPI(http.MethodPost, "/api/v1/tx/sign", signReq)
	if err != nil {
		result.ErrorText = err.Error()
		return result
	}
	result.Status = "submitted"
	result.ResultPayload = json.RawMessage(respBody)
	return result
}

func generateTxApprovalExecutionToken() (string, error) {
	buf := make([]byte, 16)
	if _, err := rand.Read(buf); err != nil {
		return "", err
	}
	return hex.EncodeToString(buf), nil
}

func ClaimTxApprovalExecution(approvalID string) (string, error) {
	if strings.TrimSpace(relayURL) == "" {
		return "", errors.New("relay url is not configured")
	}
	executionToken, err := generateTxApprovalExecutionToken()
	if err != nil {
		return "", err
	}
	body, _ := json.Marshal(map[string]any{
		"approval_id":     strings.TrimSpace(approvalID),
		"execution_token": executionToken,
	})
	resp, err := http.Post(relayURL+"/agent/tx-approval/claim", "application/json", bytes.NewReader(body))
	if err != nil {
		return "", err
	}
	defer resp.Body.Close()

	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		respBody, _ := io.ReadAll(io.LimitReader(resp.Body, 4096))
		return "", fmt.Errorf("claim failed status=%d body=%s", resp.StatusCode, strings.TrimSpace(string(respBody)))
	}

	var payload struct {
		ExecutionToken string `json:"execution_token"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&payload); err != nil {
		return "", err
	}
	if strings.TrimSpace(payload.ExecutionToken) == "" {
		return "", errors.New("claim response missing execution token")
	}
	return strings.TrimSpace(payload.ExecutionToken), nil
}

// 从 Cloud Relay 获取待审批的交易记录列表，执行已批准的交易，并汇报执行结果
func processRemoteTxApprovalsFromSnapshot(raw json.RawMessage, uid string) {
	flushPendingTxApprovalCompletions()
	uid = strings.TrimSpace(uid)
	if uid == "" || !syncRawHasData(raw) {
		return
	}

	mu.RLock()
	isActive := activated
	mu.RUnlock()
	if !isActive {
		return
	}

	var tasks []syncedTxApproval
	if err := json.Unmarshal(raw, &tasks); err != nil {
		log.Printf("[claw wallet sandbox] decode tx approvals failed uid=%s err=%v", uid, err)
		return
	}
	for _, task := range tasks {
		approvalID := strings.TrimSpace(task.ApprovalID)
		if approvalID == "" || !strings.EqualFold(strings.TrimSpace(task.UID), uid) || !strings.EqualFold(strings.TrimSpace(task.Status), "approved") {
			continue
		}
		pendingTxApprovalCompletionMu.Lock()
		_, exists := pendingTxApprovalCompletions[approvalID]
		pendingTxApprovalCompletionMu.Unlock()
		if exists {
			continue
		}
		// 领取交易 这是为了防止多线程的时候出现重复处理
		executionToken, err := ClaimTxApprovalExecution(approvalID)
		if err != nil {
			log.Printf("[claw wallet sandbox] tx approval claim failed approval_id=%s err=%v", approvalID, err)
			continue
		}
		// 重新发起交易
		completion := ExecuteApprovedTxApproval(task, executionToken)
		// 将执行结果加入待汇报列表，等待下次循环汇报给 Cloud Relay
		queuePendingTxApprovalCompletion(completion)
		// 注意这里不直接调用 flushPendingTxApprovalCompletions()，而是等处理完所有待审批交易后再统一汇报，避免频繁调用 Cloud Relay 接口
		flushPendingTxApprovalCompletions()
		return
	}
}

func ControlPlaneLoop() {
	const controlPollInterval = agentSyncHeartbeatInterval
	for {
		uid, priv := ensureControlPlaneSession()
		if uid != "" && priv != nil {
			if posted, err := postAgentSyncForUIDPeriodic(uid, priv, controlPollInterval); err != nil {
				log.Printf("[claw wallet sandbox] Control-plane agent sync failed: %v", err)
			} else if posted {
				prefetchRelayPINFromLastSync(uid, priv)
			}
		}
		if uid != "" {
			// 同步数据的主入口
			snap := agentSyncSnapshot()
			// 处理远程绑定请求（如果有）
			processRemoteBindFromSnapshot(uid, snap.BindChallenge)
			// 处理远程解绑请求（如果有）
			processRemoteWipeFromSnapshot(snap.Wipe, uid)
			// 处理沙箱更新请求（如果有）
			if err := processRemotePolicySyncFromSnapshot(uid, snap.Policy); err != nil {
				log.Printf("[claw wallet sandbox] policy sync loop failed uid=%s err=%v", uid, err)
			}
			// 处理审批交易（如果有）
			processRemoteTxApprovalsFromSnapshot(snap.TxApprovals, uid)
			// 检查沙箱更新（如果有） 1小时检查一次，确保即使没有其他操作也能及时更新
			maybeCheckForSandboxUpdate(uid)
		}
		time.Sleep(controlPollInterval)
	}
}

// 内部函数--- ⬇️⬇️⬇️⬇️⬇️⬇️ --
func ensureControlPlaneSession() (string, *ecdh.PrivateKey) {
	mu.RLock()
	uid := strings.TrimSpace(boundUid)
	mPubKey := strings.TrimSpace(masterPubKey)
	priv := ephemeralPriv
	isActive := activated
	hasRemoteManagedShare := hasRemoteManagedShareLocked()
	hasLocalShare3 := hasLegacyLocalShareLocked()
	mu.RUnlock()

	if uid == "" || mPubKey == "" {
		return "", priv
	}
	if isActive {
		return uid, priv
	}

	if hasRemoteManagedShare && !hasLocalShare3 {
		if priv == nil {
			curve := ecdh.P256()
			genPriv, err := curve.GenerateKey(rand.Reader)
			if err != nil {
				log.Printf("[claw wallet sandbox] Control-plane key generation failed: %v", err)
				return uid, nil
			}
			mu.Lock()
			if ephemeralPriv == nil {
				ephemeralPriv = genPriv
			}
			priv = ephemeralPriv
			mu.Unlock()
		}
		return uid, priv
	}
	return uid, priv
}

func executeSignSessionPayload(payload json.RawMessage) (json.RawMessage, error) {
	body, err := callLocalAPI(http.MethodPost, "/api/v1/tx/sign", payload)
	if err != nil {
		return nil, err
	}
	return json.RawMessage(body), nil
}

func activateViaRelay(priv *ecdh.PrivateKey) (string, error) {
	for {
		mu.RLock()
		uid := strings.TrimSpace(boundUid)
		mu.RUnlock()
		if _, err := postAgentSyncForUIDPeriodic(uid, priv, agentSyncRetryInterval); err != nil {
			time.Sleep(agentSyncRetryInterval)
			continue
		}
		agentSyncMu.RLock()
		pinObj := lastAgentSync.EncryptedPIN
		agentSyncMu.RUnlock()
		if pinObj != nil && pinObj.EncryptedPINHex != "" {
			pin, err := decryptRelayPIN(priv, pinObj.EncryptedPINHex, pinObj.NonceHex)
			if err == nil && strings.TrimSpace(pin) != "" {
				return pin, nil
			}
		}
		time.Sleep(agentSyncRetryInterval)
	}
}

func callLocalAPI(method, path string, payload interface{}) (string, error) {
	// 如果调用api 没有配置文件的话 直接返回错误
	envFile := ".env.clay"
	if _, err := os.Stat(envFile); os.IsNotExist(err) {
		return "", err
	}
	godotenv.Load(envFile)

	var body io.Reader
	if payload != nil {
		switch v := payload.(type) {
		case json.RawMessage:
			body = bytes.NewReader(v)
		case []byte:
			body = bytes.NewReader(v)
		default:
			data, err := json.Marshal(v)
			if err != nil {
				return "", err
			}
			body = bytes.NewReader(data)
		}
	}

	req, err := http.NewRequest(method, localAPIBaseURL()+path, body)
	if err != nil {
		return "", err
	}
	req.Header.Set("Content-Type", "application/json")
	if token := env("AGENT_TOKEN", ""); token != "" {
		req.Header.Set("Authorization", "Bearer "+token)
	}

	resp, err := (&http.Client{Timeout: 10 * time.Second}).Do(req)
	if err != nil {
		return "", fmt.Errorf("claw wallet sandbox API unavailable at %s: %w", localAPIBaseURL(), err)
	}
	defer resp.Body.Close()

	data, _ := io.ReadAll(resp.Body)
	trimmed := strings.TrimSpace(string(data))
	if trimmed == "" {
		trimmed = "{}"
	}

	var formatted bytes.Buffer
	if json.Indent(&formatted, []byte(trimmed), "", "  ") == nil {
		trimmed = formatted.String()
	}

	if resp.StatusCode >= 400 {
		return "", fmt.Errorf("%s %s failed: %s", method, path, trimmed)
	}
	return trimmed, nil
}

func localAPIBaseURL() string {
	addr := env("LISTEN_ADDR", "127.0.0.1:9000")
	if strings.HasPrefix(addr, "http://") || strings.HasPrefix(addr, "https://") {
		return strings.TrimRight(addr, "/")
	}
	if strings.HasPrefix(addr, ":") {
		addr = "127.0.0.1" + addr
	}
	return "http://" + strings.TrimRight(addr, "/")
}

func persistMigratedRemoteWalletLocked(share3 signer.EncryptedShare) error {
	encShare1 = signer.EncryptedShare{}
	encShare3 = share3
	localShare2 = signer.EncryptedShare{}
	sekKey = nil
	remoteManagedWallet = true
	lockedReason = "waiting_for_pin"
	pinExpiry = time.Time{}

	share3Data, _ := json.Marshal(share3)
	if err := utils.AtomicWrite(env("SHARE3_PATH", "share3.json"), share3Data); err != nil {
		return fmt.Errorf("failed to persist migrated share3: %w", err)
	}
	_ = os.Remove(env("SHARE1_PATH", "share1.json"))

	type identityState struct {
		MasterPubKey  string            `json:"master_pub_key"`
		Addresses     map[string]string `json:"addresses"`
		UID           string            `json:"uid"`
		WrappedSEK    string            `json:"wrapped_sek,omitempty"`
		RemoteManaged bool              `json:"remote_managed,omitempty"`
		AgentToken    string            `json:"agent_token,omitempty"`
	}
	var id identityState
	identityPath := env("IDENTITY_PATH", "identity.json")
	if data, err := os.ReadFile(identityPath); err == nil {
		_ = json.Unmarshal(data, &id)
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
	idData, _ := json.Marshal(map[string]any{
		"master_pub_key": masterPubKey,
		"addresses":      addresses,
		"uid":            boundUid,
		"remote_managed": true,
		"agent_token": func() string {
			if agentToken != "" {
				return agentToken
			}
			return env("AGENT_TOKEN", "")
		}(),
	})
	if err := utils.AtomicWrite(identityPath, idData); err != nil {
		return fmt.Errorf("failed to persist migrated identity: %w", err)
	}
	if err := EnsureWrappedSEKFile(identityPath, wrappedSEK, agentToken); err != nil {
		return fmt.Errorf("failed to persist migrated wrapped_sek.json: %w", err)
	}
	return nil
}

func activateProvisionedWithPrivLocked(pin string, priv *ecdh.PrivateKey) error {
	if masterPubKey == "" {
		return errors.New("wallet identity not initialized")
	}
	if !hasRemoteManagedShareLocked() {
		return errors.New("encrypted remote share3 is unavailable")
	}
	if priv == nil {
		return errors.New("ephemeral unlock key is unavailable")
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
	return nil
}

func syncWalletAddressesToRelay(uid string) error {
	uid = strings.TrimSpace(uid)
	if uid == "" {
		return errors.New("uid is required")
	}
	mu.RLock()
	pub := strings.TrimSpace(masterPubKey)
	addrSnapshot := make(map[string]string, len(addresses))
	for k, v := range addresses {
		addrSnapshot[k] = v
	}
	mu.RUnlock()
	if !hasNonEmptyAddresses(addrSnapshot) {
		return errors.New("local addresses are empty")
	}
	body, _ := json.Marshal(map[string]any{
		"uid":            uid,
		"master_pub_key": pub,
		"addresses":      addrSnapshot,
	})
	resp, err := http.Post(relayURL+"/agent/wallet/addresses", "application/json", bytes.NewReader(body))
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		out, _ := io.ReadAll(io.LimitReader(resp.Body, 1024))
		return fmt.Errorf("sync wallet addresses failed (%d): %s", resp.StatusCode, strings.TrimSpace(string(out)))
	}
	return nil
}

func hasNonEmptyAddresses(in map[string]string) bool {
	for chain, addr := range in {
		if strings.TrimSpace(chain) != "" && strings.TrimSpace(addr) != "" {
			return true
		}
	}
	return false
}
