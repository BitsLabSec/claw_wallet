package assets

import (
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

func TestRunFullRefreshTaskSlowChainWaitsForInflight(t *testing.T) {
	oldFn := refreshChainCacheFn
	oldRefreshing := slowChainRefreshing
	oldDone := slowChainRefreshDone
	oldStates := slowChainStates
	oldOnce := slowChainStateOnce
	t.Cleanup(func() {
		refreshChainCacheFn = oldFn
		slowChainRefreshing = oldRefreshing
		slowChainRefreshDone = oldDone
		slowChainStates = oldStates
		slowChainStateOnce = oldOnce
	})

	slowChainRefreshing = make(map[string]time.Time)
	slowChainRefreshDone = make(map[string]chan struct{})
	slowChainStates = make(map[string]slowChainState)
	slowChainStateOnce = sync.Once{}
	t.Setenv("CLAY_ASSET_CURSOR_PATH", t.TempDir()+"\\asset_cursors.json")

	started := make(chan struct{}, 1)
	var starts int32
	refreshChainCacheFn = func(chainName, address string, force bool) {
		atomic.AddInt32(&starts, 1)
		started <- struct{}{}
		time.Sleep(80 * time.Millisecond)
		finishSlowChainRefresh(chainName, address)
	}

	go runFullRefreshTask("monad", "0xabc", true)
	<-started

	waitStartedAt := time.Now()
	runFullRefreshTask("monad", "0xabc", true)
	waited := time.Since(waitStartedAt)

	if atomic.LoadInt32(&starts) != 1 {
		t.Fatalf("expected one slow refresh execution, got %d", starts)
	}
	if waited < 60*time.Millisecond {
		t.Fatalf("expected second call to wait for inflight slow refresh, waited %s", waited)
	}
}

func TestRefreshAllAutoIncludesSlowChains(t *testing.T) {
	oldFn := refreshChainCacheFn
	t.Cleanup(func() { refreshChainCacheFn = oldFn })
	t.Setenv("CLAY_ASSET_CACHE_PATH", t.TempDir()+"\\asset_cache.json")
	t.Setenv("CLAY_ASSET_CURSOR_PATH", t.TempDir()+"\\asset_cursors.json")

	var (
		mu    sync.Mutex
		calls = make(map[string]int)
		wg    sync.WaitGroup
	)
	wg.Add(len(evmRefreshChains))
	refreshChainCacheFn = func(chainName, address string, force bool) {
		defer wg.Done()
		mu.Lock()
		calls[chainName]++
		mu.Unlock()
		if IsNonBlockingRefreshChain(chainName) {
			finishSlowChainRefresh(chainName, address)
		}
	}

	RefreshAllAuto(map[string]string{"ethereum": "0xabc"})

	done := make(chan struct{})
	go func() {
		wg.Wait()
		close(done)
	}()

	select {
	case <-done:
	case <-time.After(2 * time.Second):
		t.Fatalf("timed out waiting for auto refresh calls")
	}

	for _, chain := range evmRefreshChains {
		if calls[chain] != 1 {
			t.Fatalf("expected auto refresh to include %s exactly once, got %d", chain, calls[chain])
		}
	}
}

func TestUpdateKnownContractsFromDataSeedsEVMContracts(t *testing.T) {
	oldStates := slowChainStates
	oldOnce := slowChainStateOnce
	t.Cleanup(func() {
		slowChainStates = oldStates
		slowChainStateOnce = oldOnce
	})

	slowChainStates = make(map[string]slowChainState)
	slowChainStateOnce = sync.Once{}
	t.Setenv("CLAY_ASSET_CURSOR_PATH", t.TempDir()+"\\asset_cursors.json")

	updateKnownContractsFromData("base", "0xabc", []Asset{
		{Chain: "base", ContractAddress: "native"},
		{Chain: "base", ContractAddress: "0x111"},
		{Chain: "base", ContractAddress: "0x222"},
	}, []Transaction{
		{Chain: "base", ContractAddress: "native"},
		{Chain: "base", ContractAddress: "0x333"},
	})

	state := getSlowChainState("base", "0xabc")
	if len(state.KnownContracts) != 3 {
		t.Fatalf("expected 3 known contracts, got %v", state.KnownContracts)
	}
	if state.KnownContracts[0] != "0x111" || state.KnownContracts[1] != "0x222" || state.KnownContracts[2] != "0x333" {
		t.Fatalf("unexpected known contracts snapshot: %v", state.KnownContracts)
	}
}

func TestShouldPreserveExistingAssetsWhenSlowRefreshIsSparse(t *testing.T) {
	existing := []Asset{
		{Chain: "base", ContractAddress: "native", Symbol: "ETH"},
		{Chain: "base", ContractAddress: "0x111", Symbol: "USDC"},
		{Chain: "base", ContractAddress: "0x222", Symbol: "WETH"},
	}
	incoming := []Asset{
		{Chain: "base", ContractAddress: "native", Symbol: "ETH"},
	}

	if !shouldPreserveExistingAssets("base", existing, incoming) {
		t.Fatalf("expected sparse EVM refresh to preserve existing token assets")
	}

	merged := mergeAssets(existing, incoming)
	if len(merged) != 3 {
		t.Fatalf("expected merged assets to retain cached tokens, got %d", len(merged))
	}
}
