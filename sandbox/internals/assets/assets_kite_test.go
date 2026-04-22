package assets

import "testing"

func TestKiteAssetConfig(t *testing.T) {
	if got := defaultDecimalsForChain("kite"); got != 18 {
		t.Fatalf("defaultDecimalsForChain(kite) = %d, want 18", got)
	}
	if got := assetRPCURL("kite"); got != "https://rpc.gokite.ai/" {
		t.Fatalf("assetRPCURL(kite) = %q", got)
	}
	urls := assetRPCURLs("kite")
	if len(urls) != len(kitePublicRPCs) {
		t.Fatalf("expected only kite public rpc list, got %v", urls)
	}
	if urls[0] != "https://rpc.gokite.ai/" {
		t.Fatalf("expected primary kite rpc first, got %v", urls)
	}
	if len(urls) != 1 {
		t.Fatalf("expected only official kite rpc to remain, got %v", urls)
	}
	if got := alchemyRPCURL("kite"); got != "" {
		t.Fatalf("expected kite to have no alchemy endpoint, got %q", got)
	}
	if got := getNativeSymbol("kite"); got != "KITE" {
		t.Fatalf("getNativeSymbol(kite) = %q, want KITE", got)
	}
	if got := ExplorerAddressURL("kite", "0x123"); got != "https://kitescan.ai/address/0x123" {
		t.Fatalf("ExplorerAddressURL(kite) = %q", got)
	}
	if got := ExplorerTxURL("kite", "0xabc"); got != "https://kitescan.ai/tx/0xabc" {
		t.Fatalf("ExplorerTxURL(kite) = %q", got)
	}
	if got := ExplorerTokenURL("kite", "0xtoken"); got != "https://kitescan.ai/token/0xtoken" {
		t.Fatalf("ExplorerTokenURL(kite) = %q", got)
	}
	if !containsString(evmRefreshChains, "kite") {
		t.Fatalf("evmRefreshChains missing kite: %v", evmRefreshChains)
	}
	if !supportsExplorerEVMFallback("kite") {
		t.Fatalf("expected kite to support explorer fallback")
	}
}
