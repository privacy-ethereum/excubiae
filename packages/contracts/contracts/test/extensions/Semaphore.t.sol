// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

import {Test, Vm} from "forge-std/src/Test.sol";
import {SemaphoreChecker} from "../../extensions/semaphore/SemaphoreChecker.sol";
import {SemaphoreCheckerFactory} from "../../extensions/semaphore/SemaphoreCheckerFactory.sol";
import {SemaphorePolicy} from "../../extensions/semaphore/SemaphorePolicy.sol";
import {SemaphorePolicyFactory} from "../../extensions/semaphore/SemaphorePolicyFactory.sol";
import {IPolicy} from "../../interfaces/IPolicy.sol";
import {IClone} from "../../interfaces/IClone.sol";
import {Ownable} from "@openzeppelin/contracts/access/Ownable.sol";
import {ISemaphore} from "@semaphore-protocol/contracts/interfaces/ISemaphore.sol";
import {SemaphoreMock} from "./mocks/SemaphoreMock.sol";
import {BaseCheckerMock} from "./mocks/BaseCheckerMock.sol";

contract SemaphoreCheckerTest is Test {
    SemaphoreMock internal semaphoreMock;
    SemaphoreChecker internal checker;
    SemaphoreCheckerFactory internal factory;

    address public deployer = vm.addr(0x1);
    address public guarded = vm.addr(0x2);
    address public subject = vm.addr(0x3);
    address public notSubject = vm.addr(0x4);
    uint256 public validGroupId = 0;
    uint256 public invalidGroupId = 1;

    ISemaphore.SemaphoreProof public validProof =
        ISemaphore.SemaphoreProof({
            merkleTreeDepth: 1,
            merkleTreeRoot: 0,
            nullifier: 0,
            message: uint256(uint160(subject)),
            scope: validGroupId,
            points: [uint256(0), uint256(0), uint256(0), uint256(0), uint256(0), uint256(0), uint256(0), uint256(0)]
        });

    ISemaphore.SemaphoreProof public invalidProverProof =
        ISemaphore.SemaphoreProof({
            merkleTreeDepth: 1,
            merkleTreeRoot: 0,
            nullifier: 0,
            message: uint256(uint160(notSubject)),
            scope: validGroupId,
            points: [uint256(0), uint256(0), uint256(0), uint256(0), uint256(0), uint256(0), uint256(0), uint256(0)]
        });

    ISemaphore.SemaphoreProof public invalidGroupIdProof =
        ISemaphore.SemaphoreProof({
            merkleTreeDepth: 1,
            merkleTreeRoot: 0,
            nullifier: 0,
            message: uint256(uint160(subject)),
            scope: invalidGroupId,
            points: [uint256(0), uint256(0), uint256(0), uint256(0), uint256(0), uint256(0), uint256(0), uint256(0)]
        });

    ISemaphore.SemaphoreProof public invalidProof =
        ISemaphore.SemaphoreProof({
            merkleTreeDepth: 1,
            merkleTreeRoot: 0,
            nullifier: 1,
            message: uint256(uint160(subject)),
            scope: validGroupId,
            points: [uint256(1), uint256(0), uint256(0), uint256(0), uint256(0), uint256(0), uint256(0), uint256(0)]
        });

    bytes public validEvidence = abi.encode(validProof);
    bytes public invalidProverEvidence = abi.encode(invalidProverProof);
    bytes public invalidGroupIdEvidence = abi.encode(invalidGroupIdProof);
    bytes public invalidEvidence = abi.encode(invalidProof);

    function setUp() public {
        vm.startPrank(deployer);

        uint256[] memory groupIds = new uint256[](1);
        uint256[] memory nullifiers = new uint256[](2);
        bool[] memory nullifiersValidities = new bool[](2);
        groupIds[0] = validGroupId;
        nullifiers[0] = validProof.nullifier;
        nullifiers[1] = invalidProof.nullifier;
        nullifiersValidities[0] = true;
        nullifiersValidities[1] = false;

        semaphoreMock = new SemaphoreMock(groupIds, nullifiers, nullifiersValidities);

        factory = new SemaphoreCheckerFactory();

        vm.recordLogs();
        factory.deploy(address(semaphoreMock), validGroupId);
        Vm.Log[] memory entries = vm.getRecordedLogs();
        address baseClone = address(uint160(uint256(entries[0].topics[1])));
        checker = SemaphoreChecker(baseClone);

        vm.stopPrank();
    }

    function test_factory_deployAndInitialize() public view {
        assertEq(checker.initialized(), true);
    }

    function test_checker_whenAlreadyInitialized_reverts() public {
        vm.expectRevert(abi.encodeWithSelector(IClone.AlreadyInitialized.selector));
        checker.initialize();
    }

    function test_checker_getAppendedBytes() public view {
        assertEq(checker.getAppendedBytes(), abi.encode(address(semaphoreMock), validGroupId));
    }

    function test_checker_whenScopeProverIncorrect_reverts() public {
        vm.startPrank(guarded);

        vm.expectRevert(abi.encodeWithSelector(SemaphoreChecker.InvalidProver.selector));
        checker.check(subject, invalidProverEvidence);

        vm.stopPrank();
    }

    function test_checker_whenScopeGroupIdIncorrect_reverts() public {
        vm.startPrank(guarded);

        vm.expectRevert(abi.encodeWithSelector(SemaphoreChecker.InvalidGroup.selector));
        checker.check(subject, invalidGroupIdEvidence);

        vm.stopPrank();
    }

    function test_checker_whenInvalidProof_reverts() public {
        vm.startPrank(guarded);

        vm.expectRevert(abi.encodeWithSelector(SemaphoreChecker.InvalidProof.selector));
        checker.check(subject, invalidEvidence);

        vm.stopPrank();
    }

    function test_checker_whenCallerIsOwner_succeeds() public {
        vm.startPrank(guarded);

        assert(checker.check(subject, validEvidence));

        vm.stopPrank();
    }
}

contract SemaphorePolicyTest is Test {
    event TargetSet(address indexed guarded);
    event Enforced(address indexed subject, address indexed guarded, bytes evidence);

    SemaphoreMock internal semaphoreMock;
    BaseCheckerMock internal baseCheckerMock;
    SemaphoreChecker internal checker;
    SemaphoreCheckerFactory internal factory;
    SemaphorePolicy internal policy;
    SemaphorePolicy internal policyWithCheckerMock;
    SemaphorePolicyFactory internal policyFactory;

    address public deployer = vm.addr(0x1);
    address public guarded = vm.addr(0x2);
    address public subject = vm.addr(0x3);
    address public notOwner = vm.addr(0x4);
    address public notSubject = vm.addr(0x5);
    uint256 public validGroupId = 0;
    uint256 public invalidGroupId = 1;

    ISemaphore.SemaphoreProof public validProof =
        ISemaphore.SemaphoreProof({
            merkleTreeDepth: 1,
            merkleTreeRoot: 0,
            nullifier: 0,
            message: uint256(uint160(subject)),
            scope: validGroupId,
            points: [uint256(0), uint256(0), uint256(0), uint256(0), uint256(0), uint256(0), uint256(0), uint256(0)]
        });

    ISemaphore.SemaphoreProof public invalidProverProof =
        ISemaphore.SemaphoreProof({
            merkleTreeDepth: 1,
            merkleTreeRoot: 0,
            nullifier: 0,
            message: uint256(uint160(notSubject)),
            scope: validGroupId,
            points: [uint256(0), uint256(0), uint256(0), uint256(0), uint256(0), uint256(0), uint256(0), uint256(0)]
        });

    ISemaphore.SemaphoreProof public invalidGroupIdProof =
        ISemaphore.SemaphoreProof({
            merkleTreeDepth: 1,
            merkleTreeRoot: 0,
            nullifier: 0,
            message: uint256(uint160(subject)),
            scope: invalidGroupId,
            points: [uint256(0), uint256(0), uint256(0), uint256(0), uint256(0), uint256(0), uint256(0), uint256(0)]
        });

    ISemaphore.SemaphoreProof public invalidProof =
        ISemaphore.SemaphoreProof({
            merkleTreeDepth: 1,
            merkleTreeRoot: 0,
            nullifier: 1,
            message: uint256(uint160(subject)),
            scope: validGroupId,
            points: [uint256(1), uint256(0), uint256(0), uint256(0), uint256(0), uint256(0), uint256(0), uint256(0)]
        });

    bytes public validEvidence = abi.encode(validProof);
    bytes public invalidProverEvidence = abi.encode(invalidProverProof);
    bytes public invalidGroupIdEvidence = abi.encode(invalidGroupIdProof);
    bytes public invalidEvidence = abi.encode(invalidProof);

    function setUp() public virtual {
        vm.startPrank(deployer);

        uint256[] memory groupIds = new uint256[](1);
        uint256[] memory nullifiers = new uint256[](2);
        bool[] memory nullifiersValidities = new bool[](2);
        groupIds[0] = validGroupId;
        nullifiers[0] = validProof.nullifier;
        nullifiers[1] = invalidProof.nullifier;
        nullifiersValidities[0] = true;
        nullifiersValidities[1] = false;

        semaphoreMock = new SemaphoreMock(groupIds, nullifiers, nullifiersValidities);

        baseCheckerMock = new BaseCheckerMock();

        factory = new SemaphoreCheckerFactory();
        policyFactory = new SemaphorePolicyFactory();

        vm.recordLogs();
        factory.deploy(address(semaphoreMock), validGroupId);
        Vm.Log[] memory entries = vm.getRecordedLogs();
        address baseClone = address(uint160(uint256(entries[0].topics[1])));
        checker = SemaphoreChecker(baseClone);

        vm.recordLogs();
        policyFactory.deploy(address(checker));
        entries = vm.getRecordedLogs();
        address policyClone = address(uint160(uint256(entries[0].topics[1])));
        policy = SemaphorePolicy(policyClone);

        vm.recordLogs();
        policyFactory.deploy(address(baseCheckerMock));
        entries = vm.getRecordedLogs();
        address policyCloneCheckerMock = address(uint160(uint256(entries[0].topics[1])));
        policyWithCheckerMock = SemaphorePolicy(policyCloneCheckerMock);

        vm.stopPrank();
    }

    function test_factory_deployAndInitialize() public view {
        assertEq(policy.initialized(), true);
    }

    function test_policy_whenAlreadyInitialized_reverts() public {
        vm.expectRevert(abi.encodeWithSelector(IClone.AlreadyInitialized.selector));
        policy.initialize();
    }

    function test_policy_getAppendedBytes() public view {
        assertEq(policy.getAppendedBytes(), abi.encode(address(deployer), address(checker)));
    }

    function test_policy_trait_returnsCorrectValue() public view {
        assertEq(policy.trait(), "Semaphore");
    }

    function test_policy_target_returnsExpectedAddress() public {
        vm.startPrank(deployer);

        policy.setTarget(guarded);

        assertEq(policy.guarded(), guarded);

        vm.stopPrank();
    }

    function test_policy_setTarget_whenCallerNotOwner_reverts() public {
        vm.startPrank(notOwner);

        vm.expectRevert(abi.encodeWithSelector(Ownable.OwnableUnauthorizedAccount.selector, notOwner));
        policy.setTarget(guarded);

        vm.stopPrank();
    }

    function test_policy_setTarget_whenZeroAddress_reverts() public {
        vm.startPrank(deployer);

        vm.expectRevert(abi.encodeWithSelector(IPolicy.ZeroAddress.selector));
        policy.setTarget(address(0));

        vm.stopPrank();
    }

    function test_policy_setTarget_whenValidAddress_succeeds() public {
        vm.startPrank(deployer);

        vm.expectEmit(true, true, true, true);
        emit TargetSet(guarded);

        policy.setTarget(guarded);

        vm.stopPrank();
    }

    function test_policy_setTarget_whenAlreadySet_reverts() public {
        vm.startPrank(deployer);

        policy.setTarget(guarded);

        vm.expectRevert(abi.encodeWithSelector(IPolicy.TargetAlreadySet.selector));
        policy.setTarget(guarded);

        vm.stopPrank();
    }

    function test_policy_enforce_whenScopeProverIncorrect_reverts() public {
        vm.startPrank(deployer);

        policy.setTarget(guarded);

        vm.stopPrank();

        vm.startPrank(guarded);

        vm.expectRevert(abi.encodeWithSelector(SemaphoreChecker.InvalidProver.selector));
        policy.enforce(subject, invalidProverEvidence);

        vm.stopPrank();
    }

    function test_policy_enforce_whenScopeGroupIdIncorrect_reverts() public {
        vm.startPrank(deployer);

        policy.setTarget(guarded);

        vm.stopPrank();

        vm.startPrank(guarded);

        vm.expectRevert(abi.encodeWithSelector(SemaphoreChecker.InvalidGroup.selector));
        policy.enforce(subject, invalidGroupIdEvidence);

        vm.stopPrank();
    }

    function test_policy_enforce_whenInvalidProof_reverts() public {
        vm.startPrank(deployer);

        policy.setTarget(guarded);

        vm.stopPrank();

        vm.startPrank(guarded);

        vm.expectRevert(abi.encodeWithSelector(SemaphoreChecker.InvalidProof.selector));
        policy.enforce(subject, invalidEvidence);

        vm.stopPrank();
    }

    function test_policy_enforce_whenValid_succeeds() public {
        vm.startPrank(deployer);

        policy.setTarget(guarded);

        vm.stopPrank();

        vm.startPrank(guarded);

        vm.expectEmit(true, true, true, true);
        emit Enforced(subject, guarded, validEvidence);

        policy.enforce(subject, validEvidence);

        vm.stopPrank();
    }

    function test_policy_enforce_whenAlreadyEnforced_reverts() public {
        vm.startPrank(deployer);

        policy.setTarget(guarded);

        vm.stopPrank();

        vm.startPrank(guarded);

        vm.expectEmit(true, true, true, true);
        emit Enforced(subject, guarded, validEvidence);

        policy.enforce(subject, validEvidence);

        vm.expectRevert(abi.encodeWithSelector(IPolicy.AlreadyEnforced.selector));
        policy.enforce(subject, validEvidence);

        vm.stopPrank();
    }

    function test_policyCheckerMockks_enforce_whenCheckFails_reverts() public {
        vm.startPrank(deployer);

        policyWithCheckerMock.setTarget(guarded);

        vm.stopPrank();

        vm.startPrank(guarded);

        vm.expectRevert(abi.encodeWithSelector(IPolicy.UnsuccessfulCheck.selector));
        policyWithCheckerMock.enforce(subject, validEvidence);

        vm.stopPrank();
    }
}

contract SemaphoreMockTest is Test {
    SemaphoreMock internal semaphoreMock;

    address public deployer = vm.addr(0x1);
    uint256 public validGroupId = 0;

    ISemaphore.SemaphoreProof public validProof =
        ISemaphore.SemaphoreProof({
            merkleTreeDepth: 1,
            merkleTreeRoot: 0,
            nullifier: 0,
            message: uint256(uint160(deployer)),
            scope: validGroupId,
            points: [uint256(0), uint256(0), uint256(0), uint256(0), uint256(0), uint256(0), uint256(0), uint256(0)]
        });

    function setUp() public {
        vm.startPrank(deployer);

        uint256[] memory groupIds = new uint256[](1);
        uint256[] memory nullifiers = new uint256[](1);
        bool[] memory nullifiersValidities = new bool[](1);
        groupIds[0] = validGroupId;
        nullifiers[0] = validProof.nullifier;
        nullifiersValidities[0] = true;

        semaphoreMock = new SemaphoreMock(groupIds, nullifiers, nullifiersValidities);

        vm.stopPrank();
    }

    function test_mock_deployAndStubsForCoverage() public {
        uint256[] memory dummy = new uint256[](1);
        dummy[0] = validGroupId;

        assertEq(semaphoreMock.createGroup(), 0);
        assertEq(semaphoreMock.createGroup(deployer), 0);
        assertEq(semaphoreMock.createGroup(deployer, 0), 0);

        semaphoreMock.updateGroupAdmin(0, deployer);
        semaphoreMock.acceptGroupAdmin(0);
        semaphoreMock.updateGroupMerkleTreeDuration(0, 0);
        semaphoreMock.addMember(0, 0);
        semaphoreMock.addMembers(0, dummy);
        semaphoreMock.updateMember(0, 0, 0, dummy);
        semaphoreMock.removeMember(0, 0, dummy);
        semaphoreMock.validateProof(0, validProof);
    }
}
