// SPDX-License-Identifier: MIT
pragma solidity ^0.8.28;

import "forge-std/Test.sol";

import {RecoveryVault} from "../src/RecoveryVault.sol";

contract RecoveryVaultTest is Test {
    RecoveryVault internal vault;

    address internal owner = address(0xA11CE);
    address internal stranger = address(0xB0B);

    bytes32 internal constant UID_HASH = keccak256("uid-demo");
    bytes32 internal constant SHARE2_RECEIPT = keccak256("share2-receipt");
    bytes32 internal constant SHARE2_ROOT = keccak256("share2-root");
    bytes32 internal constant SHARE2_COMMITMENT = keccak256("share2-commitment");
    bytes32 internal constant SHARE3_RECEIPT = keccak256("share3-receipt");
    bytes32 internal constant SHARE3_ROOT = keccak256("share3-root");
    bytes32 internal constant SHARE3_COMMITMENT = keccak256("share3-commitment");

    function setUp() public {
        vault = new RecoveryVault();
    }

    function testRegisterBackupStoresRecord() public {
        vm.prank(owner);
        vault.registerBackup(
            UID_HASH,
            SHARE2_RECEIPT,
            SHARE2_ROOT,
            SHARE2_COMMITMENT,
            SHARE3_RECEIPT,
            SHARE3_ROOT,
            SHARE3_COMMITMENT,
            1
        );

        RecoveryVault.Backup memory record = vault.getBackup(UID_HASH);
        assertEq(record.owner, owner);
        assertEq(record.uidHash, UID_HASH);
        assertEq(record.epoch, 1);
        assertEq(record.version, 1);
        assertTrue(record.active);
        assertEq(record.share2Receipt, SHARE2_RECEIPT);
        assertEq(record.share3Receipt, SHARE3_RECEIPT);
    }

    function testRegisterBackupOverwritesExistingRecordForSameOwner() public {
        vm.startPrank(owner);
        vault.registerBackup(
            UID_HASH,
            SHARE2_RECEIPT,
            SHARE2_ROOT,
            SHARE2_COMMITMENT,
            SHARE3_RECEIPT,
            SHARE3_ROOT,
            SHARE3_COMMITMENT,
            1
        );

        bytes32 newShare2Receipt = keccak256("share2-receipt-v2");
        bytes32 newShare2Root = keccak256("share2-root-v2");
        bytes32 newShare2Commitment = keccak256("share2-commitment-v2");
        bytes32 newShare3Receipt = keccak256("share3-receipt-v2");
        bytes32 newShare3Root = keccak256("share3-root-v2");
        bytes32 newShare3Commitment = keccak256("share3-commitment-v2");

        vault.registerBackup(
            UID_HASH,
            newShare2Receipt,
            newShare2Root,
            newShare2Commitment,
            newShare3Receipt,
            newShare3Root,
            newShare3Commitment,
            2
        );
        vm.stopPrank();

        RecoveryVault.Backup memory record = vault.getBackup(UID_HASH);
        assertEq(record.version, 2);
        assertEq(record.epoch, 2);
        assertEq(record.share2Receipt, newShare2Receipt);
        assertEq(record.share3Receipt, newShare3Receipt);
    }

    function testRegisterBackupClearsStaleReceiptLookupsOnOverwrite() public {
        vm.startPrank(owner);
        vault.registerBackup(
            UID_HASH,
            SHARE2_RECEIPT,
            SHARE2_ROOT,
            SHARE2_COMMITMENT,
            SHARE3_RECEIPT,
            SHARE3_ROOT,
            SHARE3_COMMITMENT,
            1
        );

        bytes32 newShare2Receipt = keccak256("share2-receipt-v2");
        bytes32 newShare2Root = keccak256("share2-root-v2");
        bytes32 newShare2Commitment = keccak256("share2-commitment-v2");
        bytes32 newShare3Receipt = keccak256("share3-receipt-v2");
        bytes32 newShare3Root = keccak256("share3-root-v2");
        bytes32 newShare3Commitment = keccak256("share3-commitment-v2");

        vault.registerBackup(
            UID_HASH,
            newShare2Receipt,
            newShare2Root,
            newShare2Commitment,
            newShare3Receipt,
            newShare3Root,
            newShare3Commitment,
            2
        );
        vm.stopPrank();

        vm.expectRevert(RecoveryVault.BackupNotFound.selector);
        vault.getBackupByReceipt(SHARE2_RECEIPT);

        RecoveryVault.Backup memory record = vault.getBackupByReceipt(newShare2Receipt);
        assertEq(record.share2Receipt, newShare2Receipt);
    }

    function testRegisterBackupRejectsDifferentOwnerForExistingUid() public {
        vm.prank(owner);
        vault.registerBackup(
            UID_HASH,
            SHARE2_RECEIPT,
            SHARE2_ROOT,
            SHARE2_COMMITMENT,
            SHARE3_RECEIPT,
            SHARE3_ROOT,
            SHARE3_COMMITMENT,
            1
        );

        vm.prank(stranger);
        vm.expectRevert(RecoveryVault.NotBackupOwner.selector);
        vault.registerBackup(
            UID_HASH,
            keccak256("other-s2-r"),
            keccak256("other-s2-root"),
            keccak256("other-s2-c"),
            keccak256("other-s3-r"),
            keccak256("other-s3-root"),
            keccak256("other-s3-c"),
            2
        );
    }

    function testGetBackupByReceiptReturnsMatchingRecord() public {
        vm.prank(owner);
        vault.registerBackup(
            UID_HASH,
            SHARE2_RECEIPT,
            SHARE2_ROOT,
            SHARE2_COMMITMENT,
            SHARE3_RECEIPT,
            SHARE3_ROOT,
            SHARE3_COMMITMENT,
            1
        );

        RecoveryVault.Backup memory record = vault.getBackupByReceipt(SHARE3_RECEIPT);
        assertEq(record.uidHash, UID_HASH);
        assertEq(record.share3Receipt, SHARE3_RECEIPT);
    }

    function testRevokeBackupMarksRecordInactive() public {
        vm.startPrank(owner);
        vault.registerBackup(
            UID_HASH,
            SHARE2_RECEIPT,
            SHARE2_ROOT,
            SHARE2_COMMITMENT,
            SHARE3_RECEIPT,
            SHARE3_ROOT,
            SHARE3_COMMITMENT,
            1
        );

        vault.revokeBackup(UID_HASH);
        vm.stopPrank();

        RecoveryVault.Backup memory record = vault.getBackup(UID_HASH);
        assertFalse(record.active);
    }

    function testRegisterBackupRejectsZeroUidHash() public {
        vm.prank(owner);
        vm.expectRevert(RecoveryVault.ZeroValue.selector);
        vault.registerBackup(
            bytes32(0),
            SHARE2_RECEIPT,
            SHARE2_ROOT,
            SHARE2_COMMITMENT,
            SHARE3_RECEIPT,
            SHARE3_ROOT,
            SHARE3_COMMITMENT,
            1
        );
    }

    function testRegisterBackupRejectsDuplicateShareReceipts() public {
        vm.prank(owner);
        vm.expectRevert(RecoveryVault.DuplicateShareReference.selector);
        vault.registerBackup(
            UID_HASH,
            SHARE2_RECEIPT,
            SHARE2_ROOT,
            SHARE2_COMMITMENT,
            SHARE2_RECEIPT,
            SHARE3_ROOT,
            SHARE3_COMMITMENT,
            1
        );
    }

    function testRevokeBackupRejectsDifferentOwner() public {
        vm.prank(owner);
        vault.registerBackup(
            UID_HASH,
            SHARE2_RECEIPT,
            SHARE2_ROOT,
            SHARE2_COMMITMENT,
            SHARE3_RECEIPT,
            SHARE3_ROOT,
            SHARE3_COMMITMENT,
            1
        );

        vm.prank(stranger);
        vm.expectRevert(RecoveryVault.NotBackupOwner.selector);
        vault.revokeBackup(UID_HASH);
    }
}
