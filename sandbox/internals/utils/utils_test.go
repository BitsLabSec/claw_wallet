package utils

import (
	"strings"
	"testing"
)

func TestTransferFromAddressSupportsBitcoin(t *testing.T) {
	snapshot := map[string]string{
		"bitcoin": "bc1qtestaddress",
	}
	got, err := TransferFromAddress("bitcoin", snapshot)
	if err != nil {
		t.Fatalf("expected bitcoin address, got error %v", err)
	}
	if got != "bc1qtestaddress" {
		t.Fatalf("expected bitcoin address to be returned, got %q", got)
	}
}

func TestSanitizeSensitiveTextRedactsAlchemyPathKey(t *testing.T) {
	raw := `Post "https://base-mainnet.g.alchemy.com/v2/K-MSSh4-_HlwKLogsi742": context deadline exceeded`
	got := SanitizeSensitiveText(raw)
	if got == raw {
		t.Fatalf("expected sensitive URL to change, got %q", got)
	}
	if want := `https://base-mainnet.g.alchemy.com/v2/redacted`; !strings.Contains(got, want) {
		t.Fatalf("expected redacted url %q in %q", want, got)
	}
	if strings.Contains(got, "K-MSSh4-_HlwKLogsi742") {
		t.Fatalf("expected api key to be removed, got %q", got)
	}
}

func TestSanitizeSensitiveTextRedactsAPIKeyQuery(t *testing.T) {
	raw := `Get "https://api.etherscan.io/v2/api?action=txlist&apikey=TEST_ETHERSCAN_API_KEY&chainid=143": context deadline exceeded`
	got := SanitizeSensitiveText(raw)
	if got == raw {
		t.Fatalf("expected sensitive URL to change, got %q", got)
	}
	if !strings.Contains(got, "apikey=redacted") {
		t.Fatalf("expected apikey query to be redacted, got %q", got)
	}
	if strings.Contains(got, "TEST_ETHERSCAN_API_KEY") {
		t.Fatalf("expected query api key to be removed, got %q", got)
	}
}
