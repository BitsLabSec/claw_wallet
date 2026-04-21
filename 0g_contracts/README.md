# 0G Recovery Vault Contracts

This directory contains the Foundry project for Claw's 0G recovery backup registry.

## Contract

- `RecoveryVault.sol`
  - stores the active backup locator set for a `uidHash`
  - enforces that only the original registering address can rotate or revoke a backup
  - indexes both backup receipts so recovery flows can resolve a record by `uidHash` or by `receipt`

## Main entrypoint

```solidity
function registerBackup(
    bytes32 uidHash,
    bytes32 share2Receipt,
    bytes32 share2Root,
    bytes32 share2Commitment,
    bytes32 share3Receipt,
    bytes32 share3Root,
    bytes32 share3Commitment,
    uint64 epoch
) external
```

## Local commands

```bash
forge test
forge script script/DeployRecoveryVault.s.sol:DeployRecoveryVault --rpc-url <RPC_URL> --broadcast
```

## 0G testnet deployment

Required environment variable:

```bash
PRIVATE_KEY=0x...
```

Example:

```bash
forge script script/DeployRecoveryVault.s.sol:DeployRecoveryVault \
  --rpc-url https://evmrpc-testnet.0g.ai \
  --broadcast
```
