package policy

import "testing"

func TestValidateNonTransactionSignSkipsTransferChecks(t *testing.T) {
	engine := &Engine{
		policy: &Policy{
			DailyLimitUSD:   1000,
			DailyMaxTxCount: 10,
		},
	}

	intent := &Intent{
		Chain:    "ethereum",
		SignMode: "personal_sign",
		AmountWei: "",
	}

	if err := engine.Validate(intent); err != nil {
		t.Fatalf("expected personal_sign validation to skip transfer checks, got error: %v", err)
	}
}

func TestValidateZeroValueTransactionSkipsOracleRequirement(t *testing.T) {
	engine := &Engine{
		policy: &Policy{
			DailyLimitUSD:   1000,
			DailyMaxTxCount: 10,
		},
	}

	intent := &Intent{
		Chain:     "ethereum",
		SignMode:  "transaction",
		To:        "0x0000000000000000000000000000000000000000",
		AmountWei: "0",
	}

	if err := engine.Validate(intent); err != nil {
		t.Fatalf("expected zero-value transaction to bypass oracle requirement, got error: %v", err)
	}
}
