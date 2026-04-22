package security

import "testing"

func TestChainToIDIncludesKite(t *testing.T) {
	if got := chainToID["kite"]; got != 2366 {
		t.Fatalf("chainToID[kite] = %d, want 2366", got)
	}
}

func TestChainToIDIncludesTempo(t *testing.T) {
	if got := chainToID["tempo"]; got != 42431 {
		t.Fatalf("chainToID[tempo] = %d, want 42431", got)
	}
}
