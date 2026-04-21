// SPDX-License-Identifier: MIT
pragma solidity ^0.8.28;

contract RecoveryVault {
    error ZeroValue();
    error DuplicateShareReference();
    error NotBackupOwner();
    error BackupNotFound();
    error ReceiptAlreadyInUse();

    struct Backup {
        address owner;
        bytes32 uidHash;
        bytes32 share2Receipt;
        bytes32 share2Root;
        bytes32 share2Commitment;
        bytes32 share3Receipt;
        bytes32 share3Root;
        bytes32 share3Commitment;
        uint64 epoch;
        uint64 version;
        bool active;
        uint256 updatedAt;
    }

    mapping(bytes32 uidHash => Backup backup) private backups;
    mapping(bytes32 receipt => bytes32 uidHash) private receiptToUidHash;

    event BackupRegistered(
        bytes32 indexed uidHash,
        address indexed owner,
        uint64 version,
        uint64 epoch,
        bytes32 share2Receipt,
        bytes32 share3Receipt
    );

    event BackupRevoked(bytes32 indexed uidHash, address indexed owner, uint64 version);

    function registerBackup(
        bytes32 uidHash,
        bytes32 share2Receipt,
        bytes32 share2Root,
        bytes32 share2Commitment,
        bytes32 share3Receipt,
        bytes32 share3Root,
        bytes32 share3Commitment,
        uint64 epoch
    ) external {
        _requireNonZero(uidHash);
        _requireNonZero(share2Receipt);
        _requireNonZero(share2Root);
        _requireNonZero(share2Commitment);
        _requireNonZero(share3Receipt);
        _requireNonZero(share3Root);
        _requireNonZero(share3Commitment);

        if (share2Receipt == share3Receipt || share2Root == share3Root) {
            revert DuplicateShareReference();
        }

        Backup storage current = backups[uidHash];
        if (current.owner != address(0) && current.owner != msg.sender) {
            revert NotBackupOwner();
        }

        _requireReceiptAvailable(share2Receipt, uidHash);
        _requireReceiptAvailable(share3Receipt, uidHash);

        if (current.uidHash != bytes32(0)) {
            delete receiptToUidHash[current.share2Receipt];
            delete receiptToUidHash[current.share3Receipt];
        }

        uint64 nextVersion = current.version + 1;
        backups[uidHash] = Backup({
            owner: msg.sender,
            uidHash: uidHash,
            share2Receipt: share2Receipt,
            share2Root: share2Root,
            share2Commitment: share2Commitment,
            share3Receipt: share3Receipt,
            share3Root: share3Root,
            share3Commitment: share3Commitment,
            epoch: epoch,
            version: nextVersion,
            active: true,
            updatedAt: block.timestamp
        });

        receiptToUidHash[share2Receipt] = uidHash;
        receiptToUidHash[share3Receipt] = uidHash;

        emit BackupRegistered(uidHash, msg.sender, nextVersion, epoch, share2Receipt, share3Receipt);
    }

    function revokeBackup(bytes32 uidHash) external {
        Backup storage current = backups[uidHash];
        if (current.uidHash == bytes32(0)) {
            revert BackupNotFound();
        }
        if (current.owner != msg.sender) {
            revert NotBackupOwner();
        }

        current.active = false;
        current.updatedAt = block.timestamp;

        emit BackupRevoked(uidHash, msg.sender, current.version);
    }

    function getBackup(bytes32 uidHash) external view returns (Backup memory) {
        Backup memory current = backups[uidHash];
        if (current.uidHash == bytes32(0)) {
            revert BackupNotFound();
        }
        return current;
    }

    function getBackupByReceipt(bytes32 receipt) external view returns (Backup memory) {
        bytes32 uidHash = receiptToUidHash[receipt];
        if (uidHash == bytes32(0)) {
            revert BackupNotFound();
        }

        Backup memory current = backups[uidHash];
        if (current.uidHash == bytes32(0)) {
            revert BackupNotFound();
        }
        if (current.share2Receipt != receipt && current.share3Receipt != receipt) {
            revert BackupNotFound();
        }
        return current;
    }

    function receiptOwner(bytes32 receipt) external view returns (address) {
        bytes32 uidHash = receiptToUidHash[receipt];
        if (uidHash == bytes32(0)) {
            return address(0);
        }
        return backups[uidHash].owner;
    }

    function _requireReceiptAvailable(bytes32 receipt, bytes32 uidHash) private view {
        bytes32 existingUidHash = receiptToUidHash[receipt];
        if (existingUidHash != bytes32(0) && existingUidHash != uidHash) {
            revert ReceiptAlreadyInUse();
        }
    }

    function _requireNonZero(bytes32 value) private pure {
        if (value == bytes32(0)) {
            revert ZeroValue();
        }
    }
}
