package handlers

import (
	"encoding/hex"
	"fmt"
	"math/big"
	"strconv"
	"strings"
	"time"

	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/common/hexutil"
)

func buildERC20AllowanceCalldata(owner, spender string) ([]byte, error) {
	selector := evmFunctionSelector("allowance(address,address)")
	ownerW, err := abiWordAddress(owner)
	if err != nil {
		return nil, err
	}
	spenderW, err := abiWordAddress(spender)
	if err != nil {
		return nil, err
	}
	data := make([]byte, 0, 4+32+32)
	data = append(data, selector...)
	data = append(data, ownerW...)
	data = append(data, spenderW...)
	return data, nil
}

func evmERC20Allowance(chain, tokenContract, owner, spender string) (*big.Int, error) {
	tokenContract = strings.TrimSpace(tokenContract)
	if !common.IsHexAddress(tokenContract) {
		return nil, fmt.Errorf("invalid token contract %q", tokenContract)
	}
	data, err := buildERC20AllowanceCalldata(owner, spender)
	if err != nil {
		return nil, err
	}
	call := map[string]string{
		"to":   tokenContract,
		"data": "0x" + hex.EncodeToString(data),
	}
	params := []interface{}{call, "latest"}
	var raw string
	if err := callChainRPC(chain, "eth_call", params, &raw); err != nil {
		return nil, err
	}
	if strings.TrimSpace(raw) == "" || strings.EqualFold(strings.TrimSpace(raw), "0x") {
		return big.NewInt(0), nil
	}
	b, err := hexutil.Decode(raw)
	if err != nil {
		return nil, fmt.Errorf("eth_call returned invalid hex %q: %w", raw, err)
	}
	return new(big.Int).SetBytes(b), nil
}

func evmApprovalWaitTimeout() time.Duration {
	if raw := strings.TrimSpace(env("CLAY_EVM_APPROVAL_WAIT_MS", "15000")); raw != "" {
		if ms, err := strconv.Atoi(raw); err == nil && ms > 0 {
			return time.Duration(ms) * time.Millisecond
		}
	}
	return 15 * time.Second
}

func evmApprovalPollInterval() time.Duration {
	if raw := strings.TrimSpace(env("CLAY_EVM_APPROVAL_POLL_MS", "750")); raw != "" {
		if ms, err := strconv.Atoi(raw); err == nil && ms > 0 {
			return time.Duration(ms) * time.Millisecond
		}
	}
	return 750 * time.Millisecond
}

func evmReceiptSucceeded(chain, txHash string) (bool, bool, error) {
	txHash = strings.TrimSpace(txHash)
	if txHash == "" {
		return false, false, nil
	}
	var receipt map[string]any
	if err := callChainRPC(chain, "eth_getTransactionReceipt", []interface{}{txHash}, &receipt); err != nil {
		return false, false, err
	}
	if len(receipt) == 0 {
		return false, false, nil
	}
	statusRaw, _ := receipt["status"].(string)
	statusRaw = strings.TrimSpace(statusRaw)
	if statusRaw == "" {
		return true, false, nil
	}
	status, err := hexutil.DecodeBig(statusRaw)
	if err != nil {
		return true, false, fmt.Errorf("invalid receipt status %q for %s", statusRaw, txHash)
	}
	return true, status.Sign() > 0, nil
}

func waitForERC20Allowance(chain, tokenContract, owner, spender string, want *big.Int, txHash, phase string, match func(*big.Int, *big.Int) bool) error {
	if want == nil || want.Sign() < 0 {
		return fmt.Errorf("invalid allowance target")
	}
	if match == nil {
		match = func(current, target *big.Int) bool {
			return current.Cmp(target) >= 0
		}
	}
	deadline := time.Now().Add(evmApprovalWaitTimeout())
	interval := evmApprovalPollInterval()
	var lastAllowance *big.Int
	var lastErr error
	for {
		allowance, err := evmERC20Allowance(chain, tokenContract, owner, spender)
		if err == nil {
			lastAllowance = allowance
			if match(allowance, want) {
				return nil
			}
		} else {
			lastErr = err
		}

		found, success, err := evmReceiptSucceeded(chain, txHash)
		if err != nil {
			lastErr = err
		} else if found && !success {
			return fmt.Errorf("%s transaction failed on-chain: %s", phase, txHash)
		}

		if time.Now().After(deadline) {
			if lastErr != nil {
				return fmt.Errorf("timed out waiting for %s allowance state: %w", phase, lastErr)
			}
			if lastAllowance == nil {
				return fmt.Errorf("timed out waiting for %s allowance state", phase)
			}
			return fmt.Errorf("timed out waiting for %s allowance state: current=%s target=%s", phase, lastAllowance.String(), want.String())
		}
		time.Sleep(interval)
	}
}
