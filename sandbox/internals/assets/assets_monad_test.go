package assets

import (
	"strings"
	"testing"
)

func TestMonadAssetConfig(t *testing.T) {
	if got := defaultDecimalsForChain("monad"); got != 18 {
		t.Fatalf("defaultDecimalsForChain(monad) = %d, want 18", got)
	}
	if got := assetRPCURL("monad"); got != "https://rpc2.monad.xyz" {
		t.Fatalf("assetRPCURL(monad) = %q", got)
	}
	urls := assetRPCURLs("monad")
	if len(urls) != len(monadPublicRPCs) {
		t.Fatalf("expected only monad public rpc list, got %v", urls)
	}
	if urls[0] != "https://rpc2.monad.xyz" {
		t.Fatalf("expected public rpc first, got %v", urls)
	}
	if urls[1] != "https://rpc1.monad.xyz" || urls[2] != "https://rpc3.monad.xyz" {
		t.Fatalf("expected tested monad public fallbacks first, got %v", urls)
	}
	if got := alchemyRPCURL("monad"); got != "" {
		t.Fatalf("expected monad to have no alchemy endpoint, got %q", got)
	}
	if got := getNativeSymbol("monad"); got != "MON" {
		t.Fatalf("getNativeSymbol(monad) = %q, want MON", got)
	}
	if got := ExplorerAddressURL("monad", "0x123"); got != "https://monadvision.com/address/0x123" {
		t.Fatalf("ExplorerAddressURL(monad) = %q", got)
	}
	if got := ExplorerTxURL("monad", "0xabc"); got != "https://monadvision.com/tx/0xabc" {
		t.Fatalf("ExplorerTxURL(monad) = %q", got)
	}
	if got := ExplorerTokenURL("monad", "0xtoken"); got != "https://monadvision.com/token/0xtoken" {
		t.Fatalf("ExplorerTokenURL(monad) = %q", got)
	}
	if !containsString(evmRefreshChains, "monad") {
		t.Fatalf("evmRefreshChains missing monad: %v", evmRefreshChains)
	}
}

func TestAlchemyDisableRemovesMonadFallback(t *testing.T) {
	t.Setenv(disableAlchemyEnv, "1")

	urls := assetRPCURLs("monad")
	if len(urls) != len(monadPublicRPCs) {
		t.Fatalf("expected only public monad endpoints when alchemy disabled, got %v", urls)
	}
	if urls[0] != "https://rpc2.monad.xyz" {
		t.Fatalf("expected public monad rpc only, got %v", urls)
	}
}

func TestAssetRPCURLsKeepPublicEthereumEndpointsOnly(t *testing.T) {
	urls := assetRPCURLs("ethereum")
	if len(urls) == 0 {
		t.Fatalf("expected public ethereum endpoint, got %v", urls)
	}
	if urls[0] != ethereumPublicRPCs[0] {
		t.Fatalf("expected public ethereum rpc first, got %v", urls)
	}
	for _, url := range urls {
		if strings.Contains(url, "alchemy.com") {
			t.Fatalf("did not expect alchemy endpoint in slow-path asset rpc urls, got %v", urls)
		}
	}
}

func TestRPCProxyURLsCanAppendAlchemyExceptUnsupportedChains(t *testing.T) {
	t.Setenv("CLAY_ALCHEMY_RPC_ETHEREUM", "https://eth-mainnet.g.alchemy.com/v2/test-key")

	ethereumURLs := RPCProxyURLs("ethereum")
	if len(ethereumURLs) == 0 {
		t.Fatalf("expected ethereum rpc proxy urls, got %v", ethereumURLs)
	}
	if !strings.Contains(ethereumURLs[len(ethereumURLs)-1], "alchemy.com") {
		t.Fatalf("expected ethereum rpc proxy to keep alchemy fallback, got %v", ethereumURLs)
	}

	monadURLs := RPCProxyURLs("monad")
	for _, url := range monadURLs {
		if strings.Contains(url, "alchemy.com") {
			t.Fatalf("did not expect monad rpc proxy to use alchemy, got %v", monadURLs)
		}
	}
	zeroGURLs := RPCProxyURLs("0g")
	for _, url := range zeroGURLs {
		if strings.Contains(url, "alchemy.com") {
			t.Fatalf("did not expect 0g rpc proxy to use alchemy, got %v", zeroGURLs)
		}
	}
}

func TestMonadLogsConfigSupportsWideAndNarrowProviders(t *testing.T) {
	if monadLogsChunkSize != 10_000 {
		t.Fatalf("monadLogsChunkSize = %d, want 10000", monadLogsChunkSize)
	}
	if monadLogsMinChunkSize != 100 {
		t.Fatalf("monadLogsMinChunkSize = %d, want 100", monadLogsMinChunkSize)
	}
}

func TestLogLookbackBlocksForEndpoints(t *testing.T) {
	if got := logLookbackBlocksForEndpoints([]string{"https://rpc2.monad.xyz"}); got != wideLogLookbackBlocks {
		t.Fatalf("logLookbackBlocksForEndpoints(rpc2) = %d, want %d", got, wideLogLookbackBlocks)
	}
	if got := logLookbackBlocksForEndpoints([]string{"https://rpc1.monad.xyz"}); got != narrowLogLookbackBlocks {
		t.Fatalf("logLookbackBlocksForEndpoints(rpc1) = %d, want %d", got, narrowLogLookbackBlocks)
	}
	if got := logLookbackBlocksForEndpoints([]string{"https://rpc.monad.xyz"}); got != narrowLogLookbackBlocks {
		t.Fatalf("logLookbackBlocksForEndpoints(rpc.monad.xyz) = %d, want %d", got, narrowLogLookbackBlocks)
	}
	if got := logLookbackBlocksForEndpoints([]string{"https://eth.drpc.org"}); got != wideLogLookbackBlocks {
		t.Fatalf("logLookbackBlocksForEndpoints(drpc) = %d, want %d", got, wideLogLookbackBlocks)
	}
	if got := logLookbackBlocksForEndpoints([]string{"https://ethereum.publicnode.com"}); got != narrowLogLookbackBlocks {
		t.Fatalf("logLookbackBlocksForEndpoints(publicnode) = %d, want %d", got, narrowLogLookbackBlocks)
	}
}

func TestEndpointSupportsAlchemyRPC(t *testing.T) {
	if !endpointSupportsAlchemyRPC("https://eth-mainnet.g.alchemy.com/v2/test") {
		t.Fatalf("expected alchemy endpoint to be detected")
	}
	if endpointSupportsAlchemyRPC("https://eth.drpc.org") {
		t.Fatalf("did not expect public endpoint to be treated as alchemy")
	}
}

func TestExplorerFallbackEnabled(t *testing.T) {
	if !explorerFallbackEnabled() {
		t.Fatalf("expected explorer fallback enabled by default")
	}
	t.Setenv(disableExplorerFallbackEnv, "1")
	if explorerFallbackEnabled() {
		t.Fatalf("expected explorer fallback disabled by env")
	}
}

func TestShouldUseExplorerFallback(t *testing.T) {
	if !shouldUseExplorerFallback("base", []string{"https://rpc.sentio.xyz/base"}) {
		t.Fatalf("expected explorer fallback for public base endpoint")
	}
	if shouldUseExplorerFallback("base", []string{"https://base-mainnet.g.alchemy.com/v2/test"}) {
		t.Fatalf("did not expect explorer fallback when alchemy endpoint is primary")
	}
	t.Setenv(disableExplorerFallbackEnv, "1")
	if shouldUseExplorerFallback("base", []string{"https://rpc.sentio.xyz/base"}) {
		t.Fatalf("did not expect explorer fallback when disabled by env")
	}
}

func containsString(items []string, want string) bool {
	for _, item := range items {
		if item == want {
			return true
		}
	}
	return false
}
