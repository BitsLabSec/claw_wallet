// sandbox/internals/policy/policy.go
// 风控策略引擎：加载并校验交易意图是否符合用户设定的限制
package policy

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"math/big"
	"os"
	"path/filepath"
	"sandbox/internals/assets"
	"sandbox/internals/oracle"
	"sandbox/internals/security"
	"strconv"
	"strings"
	"sync"
	"time"
)

var trackerPath = "daily.json"

func LoadTracker(path string) {
	if path != "" {
		trackerPath = path
	}
	data, err := os.ReadFile(trackerPath)
	if err == nil {
		var state struct {
			Date     string  `json:"date"`
			SpentWei string  `json:"spent_wei"`
			SpentUSD float64 `json:"spent_usd"`
			TxCount  int     `json:"tx_count"`
		}
		if json.Unmarshal(data, &state) == nil {
			dailyTracker.mu.Lock()
			if state.Date == today() && state.SpentWei != "" {
				dailyTracker.date = state.Date
				n, ok := new(big.Int).SetString(state.SpentWei, 10)
				if ok {
					dailyTracker.spentWei = n
				}
				dailyTracker.spentUSD = state.SpentUSD
				dailyTracker.txCount = state.TxCount
			}
			dailyTracker.mu.Unlock()
		}
	}
}

// simple atomic write for policy pkg
func atomicWritePolicy(path string, data []byte) error {
	tmp := path + ".tmp"
	f, err := os.OpenFile(tmp, os.O_WRONLY|os.O_CREATE|os.O_TRUNC, 0600)
	if err != nil {
		return err
	}
	f.Write(data)
	f.Sync()
	f.Close()
	if err := os.Rename(tmp, path); err != nil {
		if removeErr := os.Remove(path); removeErr != nil && !errors.Is(removeErr, os.ErrNotExist) {
			return removeErr
		}
		return os.Rename(tmp, path)
	}
	return nil
}

func saveTracker() {
	dailyTracker.mu.Lock()
	defer dailyTracker.mu.Unlock()

	var state struct {
		Date     string  `json:"date"`
		SpentWei string  `json:"spent_wei"`
		SpentUSD float64 `json:"spent_usd"`
		TxCount  int     `json:"tx_count"`
	}
	state.Date = dailyTracker.date
	state.TxCount = dailyTracker.txCount
	state.SpentUSD = dailyTracker.spentUSD
	if dailyTracker.spentWei != nil {
		state.SpentWei = dailyTracker.spentWei.String()
	} else {
		state.SpentWei = "0"
	}
	if data, err := json.Marshal(state); err == nil {
		atomicWritePolicy(trackerPath, data)
	}
}

// AddressNote pairs an address with an optional label/remark
type AddressNote struct {
	Address string `json:"address"`
	Note    string `json:"note"`
	Chain   string `json:"chain"` // optional: filter by chain
}

// Policy defines the allowed transaction rules set by the user
type Policy struct {
	MaxAmountPerTxUSD            float64       `json:"max_amount_per_tx_usd"`           // max spend per tx in USD
	DailyLimitUSD                float64       `json:"daily_limit_usd"`                 // primary: per-day spend cap in USD
	WhitelistTo                  []AddressNote `json:"whitelist_to"`                    // allowed destination addresses
	BlacklistTo                  []AddressNote `json:"blacklist_to"`                    // FORCED blocked addresses
	PinTTLSeconds                int64         `json:"pin_ttl_seconds"`                 // Session TTL
	DailyMaxTxCount              int           `json:"daily_max_tx_count"`              // Max tx per 24h
	UnpricedAssetPolicy          string        `json:"unpriced_asset_policy"`           // "allow" or "block"
	BlockHighRiskTokens          bool          `json:"block_high_risk_tokens"`          // default true
	AllowBlindSign               bool          `json:"allow_blind_sign"`                // default false
	StrictPlainText              bool          `json:"strict_plain_text"`               // enforce personal_sign guardrails
	KeepShare2Resident           bool          `json:"keep_share2_resident"`            // allow encrypted share2 to persist in memory across TTL expiry
	PersonalSignKeywordBlacklist []string      `json:"personal_sign_keyword_blacklist"` // phrase denylist for message signing
}

// DailyTracker accumulates daily spending in both Wei and USD
type DailyTracker struct {
	mu       sync.Mutex
	date     string
	spentWei *big.Int
	spentUSD float64
	txCount  int
}

var dailyTracker = &DailyTracker{spentWei: big.NewInt(0), spentUSD: 0, txCount: 0}

func today() string { return time.Now().UTC().Format("2006-01-02") }

// Add records a transaction's spend in both Wei and USD
func (t *DailyTracker) Add(amtWei *big.Int, usdValue float64) error {
	t.mu.Lock()
	if t.date != today() {
		t.date = today()
		t.spentWei = big.NewInt(0)
		t.spentUSD = 0
		t.txCount = 0
	}
	t.spentWei.Add(t.spentWei, amtWei)
	t.spentUSD += usdValue
	t.txCount++
	t.mu.Unlock()

	// Persist changes asynchronously
	go saveTracker()
	return nil
}

func (t *DailyTracker) SpentUSD() float64 {
	t.mu.Lock()
	defer t.mu.Unlock()
	if t.date != today() {
		return 0
	}
	return t.spentUSD
}

func (t *DailyTracker) Spent() *big.Int {
	t.mu.Lock()
	defer t.mu.Unlock()
	if t.date != today() {
		return big.NewInt(0)
	}
	return new(big.Int).Set(t.spentWei)
}

// Engine holds the active policy and validates intents
type Engine struct {
	mu     sync.RWMutex
	policy *Policy
	path   string
}

type UsageSnapshot struct {
	LocalSpentWei     string  `json:"local_spent_wei"`
	LocalSpentUSD     float64 `json:"local_spent_usd"`
	LocalTxCount      int     `json:"local_tx_count"`
	OnChainSpentUSD   float64 `json:"onchain_spent_usd"`
	OnChainTxCount    int     `json:"onchain_tx_count"`
	EffectiveSpentUSD float64 `json:"effective_spent_usd"`
	EffectiveTxCount  int     `json:"effective_tx_count"`
}

func defaultPolicy() Policy {
	return Policy{
		MaxAmountPerTxUSD:            100.0,
		DailyLimitUSD:                1000.0,
		WhitelistTo:                  []AddressNote{},
		BlacklistTo:                  []AddressNote{},
		PinTTLSeconds:                86400,
		DailyMaxTxCount:              1000,
		UnpricedAssetPolicy:          "block",
		BlockHighRiskTokens:          true,
		AllowBlindSign:               false,
		StrictPlainText:              true,
		KeepShare2Resident:           false,
		PersonalSignKeywordBlacklist: DefaultPersonalSignKeywordBlacklist(),
	}
}

// Current returns the current active policy
func (e *Engine) Current() Policy {
	e.mu.RLock()
	defer e.mu.RUnlock()
	if e.policy == nil {
		return defaultPolicy()
	}
	return *e.policy
}

func (e *Engine) UsageSnapshot() UsageSnapshot {
	localUSD := dailyTracker.SpentUSD()
	localTxCount := dailyTracker.Count()
	localWei := dailyTracker.Spent().String()
	onChain := assets.DailyUsageSnapshot()

	effectiveUSD := localUSD
	if onChain.SpentUSD > effectiveUSD {
		effectiveUSD = onChain.SpentUSD
	}

	effectiveTxCount := localTxCount
	if onChain.TxCount > effectiveTxCount {
		effectiveTxCount = onChain.TxCount
	}

	return UsageSnapshot{
		LocalSpentWei:     localWei,
		LocalSpentUSD:     localUSD,
		LocalTxCount:      localTxCount,
		OnChainSpentUSD:   onChain.SpentUSD,
		OnChainTxCount:    onChain.TxCount,
		EffectiveSpentUSD: effectiveUSD,
		EffectiveTxCount:  effectiveTxCount,
	}
}

// TodaySpentWei returns the cumulative spent amount today in Wei as a string
func (e *Engine) TodaySpentWei() string {
	return e.UsageSnapshot().LocalSpentWei
}

// TodaySpentUSD returns the cumulative spent amount today in USD
func (e *Engine) TodaySpentUSD() float64 {
	return e.UsageSnapshot().EffectiveSpentUSD
}

// TodayTxCount returns the number of transactions signed today
func (e *Engine) TodayTxCount() int {
	return e.UsageSnapshot().EffectiveTxCount
}

// NewEngine loads policy from the given JSON file path
func NewEngine(policyPath string) (*Engine, error) {
	e := &Engine{path: policyPath}
	if err := e.Reload(); err != nil {
		p := defaultPolicy()
		e.mu.Lock()
		e.policy = &p
		e.mu.Unlock()
		return e, err
	}
	return e, nil
}

// Reload hot-reloads the policy JSON from disk
func (e *Engine) Reload() error {
	data, encrypted, err := readStoredPolicyBytes(e.path)
	if err != nil {
		if os.IsNotExist(err) {
			os.MkdirAll(filepath.Dir(e.path), 0755)
			p := defaultPolicy()
			data, _ = json.MarshalIndent(p, "", "  ")
			if writeErr := WriteStoredPolicyBytes(e.path, data); writeErr != nil && !errors.Is(writeErr, ErrPolicyEncryptionUnavailable) {
				return fmt.Errorf("policy file write error: %w", writeErr)
			}
		} else {
			return fmt.Errorf("policy file read error: %w", err)
		}
	}
	var p Policy
	if err := json.Unmarshal(data, &p); err != nil {
		return fmt.Errorf("policy parse error: %w", err)
	}
	if !bytes.Contains(data, []byte(`"block_high_risk_tokens"`)) {
		p.BlockHighRiskTokens = true
	}
	if !bytes.Contains(data, []byte(`"allow_blind_sign"`)) {
		if bytes.Contains(data, []byte(`"block_blind_hex"`)) {
			var legacy struct {
				BlockBlindHex bool `json:"block_blind_hex"`
			}
			if json.Unmarshal(data, &legacy) == nil {
				p.AllowBlindSign = !legacy.BlockBlindHex
			}
		} else {
			p.AllowBlindSign = false
		}
	}
	if !bytes.Contains(data, []byte(`"strict_plain_text"`)) {
		p.StrictPlainText = true
	}
	if !bytes.Contains(data, []byte(`"personal_sign_keyword_blacklist"`)) || len(p.PersonalSignKeywordBlacklist) == 0 {
		p.PersonalSignKeywordBlacklist = DefaultPersonalSignKeywordBlacklist()
	}
	if !bytes.Contains(data, []byte(`"pin_ttl_seconds"`)) {
		p.PinTTLSeconds = 86400 // Default to 24 hours when omitted
	}
	if p.PinTTLSeconds < 0 {
		p.PinTTLSeconds = 86400 // Negative values are invalid and fall back to default
	}
	if !encrypted {
		payload, marshalErr := json.MarshalIndent(p, "", "  ")
		if marshalErr == nil {
			if writeErr := WriteStoredPolicyBytes(e.path, payload); writeErr != nil && !errors.Is(writeErr, ErrPolicyEncryptionUnavailable) {
				return fmt.Errorf("policy file migration error: %w", writeErr)
			}
		}
	}
	e.mu.Lock()
	e.policy = &p
	e.mu.Unlock()
	return nil
}

// GetTTL returns the configured PIN Time-To-Live
func (e *Engine) GetTTL() int64 {
	e.mu.RLock()
	defer e.mu.RUnlock()
	if e.policy == nil {
		return 86400
	}
	return e.policy.PinTTLSeconds
}

func (e *Engine) KeepShare2ResidentEnabled() bool {
	e.mu.RLock()
	defer e.mu.RUnlock()
	if e.policy == nil {
		return false
	}
	return e.policy.KeepShare2Resident
}

// Intent is the request from Clawbot
type Intent struct {
	Chain         string `json:"chain"`          // "ethereum" | "solana"
	SignMode      string `json:"sign_mode"`      // transaction | swap | bridge | personal_sign | typed_data | raw_hash
	To            string `json:"to"`             // destination address (for tokens, this might be the contract or the recipient)
	TokenContract string `json:"token_contract"` // optional: for ERC20/SPL tokens
	AmountWei     string `json:"amount_wei"`     // in wei or token units (string to avoid overflow)
	Data          string `json:"data"`           // hex-encoded calldata (optional)
	Nonce         uint64 `json:"nonce"`
}

func intentRequiresTransferChecks(intent *Intent) bool {
	if intent == nil {
		return false
	}
	mode := strings.ToLower(strings.TrimSpace(intent.SignMode))
	return mode == "" || mode == "transaction" || mode == "swap" || mode == "bridge"
}

func intentSkipsAddressListChecks(intent *Intent) bool {
	if intent == nil {
		return false
	}
	mode := strings.TrimSpace(intent.SignMode)
	return strings.EqualFold(mode, "swap") || strings.EqualFold(mode, "bridge")
}

func intentMatchesAddressNotes(intent *Intent, notes []AddressNote) bool {
	if intent == nil || len(notes) == 0 {
		return false
	}
	for _, item := range notes {
		if !strings.EqualFold(item.Address, intent.To) {
			continue
		}
		if item.Chain != "" && !strings.EqualFold(item.Chain, intent.Chain) {
			continue
		}
		return true
	}
	return false
}

// Validate checks whether the intent passes all policy rules
func (e *Engine) Validate(intent *Intent) error {
	e.mu.RLock()
	p := e.policy
	e.mu.RUnlock()

	if !intentRequiresTransferChecks(intent) {
		return nil
	}

	// 1. Recipient whitelist
	if !intentSkipsAddressListChecks(intent) && len(p.WhitelistTo) > 0 {
		if !intentMatchesAddressNotes(intent, p.WhitelistTo) {
			return fmt.Errorf("recipient '%s' (chain: %s) not in whitelist_to", intent.To, intent.Chain)
		}
	}

	// 2. Amount parsing (always enforce valid amount format)
	amt := new(big.Int)
	if _, ok := amt.SetString(intent.AmountWei, 10); !ok {
		return errors.New("invalid amount_wei: cannot parse")
	}
	isZeroValue := amt.Sign() == 0

	localSpentUSD := dailyTracker.SpentUSD()
	localTxCount := dailyTracker.Count()

	// Fast-path rejection: if local counters already breach the limits,
	// skip the more expensive on-chain usage reconciliation.
	if p.DailyLimitUSD > 0 && localSpentUSD >= p.DailyLimitUSD {
		return fmt.Errorf("daily USD spend limit exceeded: current %.2f >= limit %.2f", localSpentUSD, p.DailyLimitUSD)
	}
	if p.DailyMaxTxCount > 0 && localTxCount >= p.DailyMaxTxCount {
		return fmt.Errorf("daily transaction count limit reached: %d/%d", localTxCount, p.DailyMaxTxCount)
	}

	onChainUsage := assets.DailyUsageSnapshot()
	effectiveSpentUSD := localSpentUSD
	if onChainUsage.SpentUSD > effectiveSpentUSD {
		effectiveSpentUSD = onChainUsage.SpentUSD
	}
	effectiveTxCount := localTxCount
	if onChainUsage.TxCount > effectiveTxCount {
		effectiveTxCount = onChainUsage.TxCount
	}

	// Security Risk Check (NEW: OKX Integration)
	if intent.TokenContract != "" && p.BlockHighRiskTokens {
		risk := security.CheckTokenRisk(intent.Chain, intent.TokenContract)
		if risk.RiskLevel >= 4 {
			return fmt.Errorf("risk control: HIGH RISK token detected (%s). Transaction blocked by safety policy.", risk.RiskLabel)
		}
	}

	// 4. USD-based daily limit (primary) with oracle, fallback to Wei-based
	// Check if the recipient is whitelisted — whitelisted addrs bypass oracle-unavailable block
	// but still accumulate toward the daily limit.
	isWhitelisted := !intentSkipsAddressListChecks(intent) && intentMatchesAddressNotes(intent, p.WhitelistTo)

	if p.DailyLimitUSD > 0 && !isZeroValue {
		var price float64
		var priceOK bool

		if intent.TokenContract != "" {
			price, priceOK = oracle.GetToken(intent.Chain, intent.TokenContract, "unknown")
		} else {
			price, priceOK = oracle.Get(intent.Chain)
		}

		if !priceOK {
			// If we have no price, and it's not whitelisted, we MUST check policy
			if !isWhitelisted {
				if intent.TokenContract != "" && p.UnpricedAssetPolicy == "block" {
					return fmt.Errorf("risk control: unpriced token '%s' blocked by policy", intent.TokenContract)
				}
				// Point 4: Or if it's native and too stale
				if intent.TokenContract == "" {
					return errors.New("risk control: price oracle unavailable (>30m stale) for a non-whitelisted address")
				}
			}
			// If "allow" or whitelisted, we continue without USD check
		} else {
			// Price is OK, calculate USD value
			amtF, _ := strconv.ParseFloat(intent.AmountWei, 64)
			dec := assets.TokenDecimals(intent.Chain, intent.TokenContract)
			divisor := 1.0
			for i := 0; i < dec; i++ {
				divisor *= 10
			}
			valUSD := (amtF / divisor) * price

			if p.MaxAmountPerTxUSD > 0 && valUSD > p.MaxAmountPerTxUSD {
				return fmt.Errorf("per-tx USD spend limit exceeded: intent %.2f > limit %.2f", valUSD, p.MaxAmountPerTxUSD)
			}

			if effectiveSpentUSD+valUSD > p.DailyLimitUSD {
				return fmt.Errorf("daily USD spend limit exceeded: current %.2f + intent %.2f > limit %.2f", effectiveSpentUSD, valUSD, p.DailyLimitUSD)
			}
		}
	}

	// 5. Blacklist check
	if !intentSkipsAddressListChecks(intent) {
		for _, item := range p.BlacklistTo {
			if strings.EqualFold(item.Address, intent.To) {
				if item.Chain == "" || strings.EqualFold(item.Chain, intent.Chain) {
					return fmt.Errorf("recipient '%s' (chain: %s) is BLACKLISTED", intent.To, intent.Chain)
				}
			}
		}
	}

	// 6. Daily Tx Count limit
	if p.DailyMaxTxCount > 0 && effectiveTxCount >= p.DailyMaxTxCount {
		return fmt.Errorf("daily transaction count limit reached: %d/%d", effectiveTxCount, p.DailyMaxTxCount)
	}

	return nil
}

func (t *DailyTracker) Count() int {
	t.mu.Lock()
	defer t.mu.Unlock()
	if t.date != today() {
		return 0
	}
	return t.txCount
}

// Commit records the spend after a successful signing
// Fetches oracle price to record USD equivalent
func (e *Engine) Commit(intent *Intent) {
	if !intentRequiresTransferChecks(intent) {
		return
	}
	amt := new(big.Int)
	amt.SetString(intent.AmountWei, 10)

	// Compute USD value for tracking
	var usdValue float64
	var (
		price float64
		ok    bool
	)
	if intent.TokenContract != "" {
		price, ok = oracle.GetToken(intent.Chain, intent.TokenContract, "unknown")
	} else {
		price, ok = oracle.Get(intent.Chain)
	}
	if ok {
		amtF, _ := new(big.Float).SetInt(amt).Float64()
		divisor := 1.0
		for i := 0; i < assets.TokenDecimals(intent.Chain, intent.TokenContract); i++ {
			divisor *= 10
		}
		usdValue = (amtF / divisor) * price
	}
	dailyTracker.Add(amt, usdValue)
}

func DefaultPersonalSignKeywordBlacklist() []string {
	return []string{
		"access my seed",
		"seed phrase",
		"private key",
		"recovery phrase",
		"sign over control",
		"transfer ownership",
	}
}
