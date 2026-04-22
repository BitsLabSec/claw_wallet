package assets

import (
	"os"
	"path/filepath"
	"sync"
	"testing"
	"time"
)

func TestTryStartSlowChainRefreshDedupesByKey(t *testing.T) {
	prevRefreshing := slowChainRefreshing
	slowChainRefreshing = make(map[string]time.Time)
	t.Cleanup(func() {
		slowChainRefreshing = prevRefreshing
	})

	if !tryStartSlowChainRefresh("monad", "0xabc") {
		t.Fatal("expected first refresh attempt to start")
	}
	if tryStartSlowChainRefresh("monad", "0xabc") {
		t.Fatal("expected duplicate refresh attempt to be rejected")
	}

	finishSlowChainRefresh("monad", "0xabc")

	if !tryStartSlowChainRefresh("monad", "0xabc") {
		t.Fatal("expected refresh to restart after finish")
	}
}

func TestPruneSlowChainStatesLockedEvictsOldestNonInflight(t *testing.T) {
	prevStates := slowChainStates
	prevRefreshing := slowChainRefreshing
	slowChainStates = map[string]slowChainState{
		"monad:old": {
			LastTouchedAt: time.Unix(10, 0),
		},
		"monad:keep": {
			LastTouchedAt: time.Unix(20, 0),
		},
		"0g:inflight": {
			LastTouchedAt: time.Unix(5, 0),
		},
	}
	slowChainRefreshing = map[string]time.Time{
		"0g:inflight": time.Unix(30, 0),
	}
	t.Cleanup(func() {
		slowChainStates = prevStates
		slowChainRefreshing = prevRefreshing
	})

	slowChainMu.Lock()
	pruneSlowChainStatesLocked(2)
	slowChainMu.Unlock()

	if _, ok := slowChainStates["monad:old"]; ok {
		t.Fatal("expected oldest non-inflight state to be pruned")
	}
	if _, ok := slowChainStates["monad:keep"]; !ok {
		t.Fatal("expected newer state to remain")
	}
	if _, ok := slowChainStates["0g:inflight"]; !ok {
		t.Fatal("expected inflight state to remain")
	}
}

func TestGetSlowChainStateTouchesExistingEntry(t *testing.T) {
	prevStates := slowChainStates
	slowChainStates = map[string]slowChainState{
		"0g:0xabc": {
			LastTouchedAt: time.Time{},
		},
	}
	t.Cleanup(func() {
		slowChainStates = prevStates
	})

	state := getSlowChainState("0g", "0xabc")
	if state.LastTouchedAt.IsZero() {
		t.Fatal("expected returned state to include refreshed LastTouchedAt")
	}
	if slowChainStates["0g:0xabc"].LastTouchedAt.IsZero() {
		t.Fatal("expected cached state to record LastTouchedAt")
	}
}

func TestUpdateSlowChainStatePersistsAndReloads(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "asset_cursors.json")
	t.Setenv("CLAY_ASSET_CURSOR_PATH", path)

	prevStates := slowChainStates
	prevRefreshing := slowChainRefreshing
	prevOnce := slowChainStateOnce
	slowChainStates = make(map[string]slowChainState)
	slowChainRefreshing = make(map[string]time.Time)
	slowChainStateOnce = sync.Once{}
	t.Cleanup(func() {
		slowChainStates = prevStates
		slowChainRefreshing = prevRefreshing
		slowChainStateOnce = prevOnce
	})

	updateSlowChainState("arbitrum", "0xabc", func(state *slowChainState) {
		state.ContractScanBlock = 123
		state.HistoryScanBlock = 456
		state.KnownContracts = []string{"0xdef"}
		state.LastNativeTxCount = 3
	})

	if _, err := os.Stat(path); err != nil {
		t.Fatalf("expected persisted cursor file: %v", err)
	}

	slowChainStates = make(map[string]slowChainState)
	slowChainRefreshing = make(map[string]time.Time)
	slowChainStateOnce = sync.Once{}

	state := getSlowChainState("arbitrum", "0xabc")
	if state.ContractScanBlock != 123 {
		t.Fatalf("expected persisted ContractScanBlock=123, got %d", state.ContractScanBlock)
	}
	if state.HistoryScanBlock != 456 {
		t.Fatalf("expected persisted HistoryScanBlock=456, got %d", state.HistoryScanBlock)
	}
	if state.LastNativeTxCount != 3 {
		t.Fatalf("expected persisted LastNativeTxCount=3, got %d", state.LastNativeTxCount)
	}
	if len(state.KnownContracts) != 1 || state.KnownContracts[0] != "0xdef" {
		t.Fatalf("expected persisted KnownContracts, got %+v", state.KnownContracts)
	}
}

func TestUsesPersistentCursorChainIncludesFastFallbackChains(t *testing.T) {
	for _, chain := range []string{"ethereum", "base", "bsc", "arbitrum", "optimism", "polygon", "0g", "monad"} {
		if !usesPersistentCursorChain(chain) {
			t.Fatalf("expected %s to use persistent cursor state", chain)
		}
	}
	if usesPersistentCursorChain("solana") {
		t.Fatal("did not expect solana to use EVM cursor state")
	}
}
