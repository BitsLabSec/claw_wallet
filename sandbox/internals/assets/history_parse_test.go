package assets

import (
	"math/big"
	"testing"
)

func TestParseSolanaTransactionIncludesIncomingNative(t *testing.T) {
	txs := parseSolanaTransaction("owner", "sig1", 0, map[string]interface{}{
		"blockTime": float64(1_700_000_000),
		"transaction": map[string]interface{}{
			"message": map[string]interface{}{
				"accountKeys": []interface{}{"owner"},
			},
		},
		"meta": map[string]interface{}{
			"err":         nil,
			"fee":         float64(5000),
			"preBalances": []interface{}{float64(1_000_000_000)},
			"postBalances": []interface{}{
				float64(1_500_000_000),
			},
		},
	})

	if len(txs) != 1 {
		t.Fatalf("expected 1 tx, got %d", len(txs))
	}
	if txs[0].Direction != "incoming" {
		t.Fatalf("expected incoming direction, got %+v", txs[0])
	}
}

func TestParseSuiTransactionIncludesIncomingBalanceChange(t *testing.T) {
	txs := parseSuiTransaction("owner", "", map[string]interface{}{
		"digest":      "digest1",
		"timestampMs": "1700000000000",
		"transaction": map[string]interface{}{
			"data": map[string]interface{}{
				"sender": "sender1",
			},
		},
		"balanceChanges": []interface{}{
			map[string]interface{}{
				"owner":    map[string]interface{}{"AddressOwner": "owner"},
				"coinType": "0x2::sui::SUI",
				"amount":   "1000000000",
			},
		},
	})

	if len(txs) != 1 {
		t.Fatalf("expected 1 tx, got %d", len(txs))
	}
	if txs[0].Direction != "incoming" || txs[0].To != "owner" {
		t.Fatalf("expected incoming tx to owner, got %+v", txs[0])
	}
}

func TestBitcoinTxToHistoryRowKeepsOlderTransactions(t *testing.T) {
	row, keep := bitcoinTxToHistoryRow("addr1", bitcoinTxResponse{
		TxID: "tx1",
		Status: bitcoinTxStatus{
			Confirmed: true,
			BlockTime: 1_600_000_000,
		},
		Vout: []bitcoinTxVout{
			{ScriptPubKeyAddress: "addr1", Value: 50_000},
		},
	})
	if !keep {
		t.Fatalf("expected older bitcoin transaction to be kept")
	}
	if row.Direction != "incoming" {
		t.Fatalf("expected incoming bitcoin tx, got %+v", row)
	}
}

func TestParseSolanaTransactionIncludesIncomingTokenDelta(t *testing.T) {
	txs := parseSolanaTransaction("owner", "sig2", 0, map[string]interface{}{
		"blockTime": float64(1_700_000_000),
		"transaction": map[string]interface{}{
			"message": map[string]interface{}{
				"accountKeys": []interface{}{"owner"},
			},
		},
		"meta": map[string]interface{}{
			"err":         nil,
			"fee":         float64(5000),
			"preBalances": []interface{}{float64(1_000_000_000)},
			"postBalances": []interface{}{
				float64(1_000_000_000),
			},
			"preTokenBalances": []interface{}{
				map[string]interface{}{
					"owner": "owner",
					"mint":  "mint1",
					"uiTokenAmount": map[string]interface{}{
						"amount":   "0",
						"decimals": float64(6),
					},
				},
			},
			"postTokenBalances": []interface{}{
				map[string]interface{}{
					"owner": "owner",
					"mint":  "mint1",
					"uiTokenAmount": map[string]interface{}{
						"amount":   big.NewInt(1000).String(),
						"decimals": float64(6),
					},
				},
			},
		},
	})

	if len(txs) != 1 {
		t.Fatalf("expected 1 token tx, got %d", len(txs))
	}
	if txs[0].Direction != "incoming" || txs[0].ContractAddress != "mint1" {
		t.Fatalf("expected incoming token tx, got %+v", txs[0])
	}
}
