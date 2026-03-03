// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

import { Test, Vm } from "forge-std/src/Test.sol";
import { NFT } from "./utils/NFT.sol";
import { BaseERC721Checker } from "./base/BaseERC721Checker.sol";
import { BaseERC721CheckerFactory } from "./base/BaseERC721CheckerFactory.sol";
import { BaseERC721PolicyFactory } from "./base/BaseERC721PolicyFactory.sol";
import { BaseERC721Policy } from "./base/BaseERC721Policy.sol";
import { BaseVoting } from "./base/BaseVoting.sol";
import { IPolicy } from "../../interfaces/IPolicy.sol";
import { IClone } from "../../interfaces/IClone.sol";
import { IERC721Errors } from "@openzeppelin/contracts/interfaces/draft-IERC6093.sol";
import { Ownable } from "@openzeppelin/contracts/access/Ownable.sol";

contract BaseChecker is Test {
    NFT internal nft;
    BaseERC721Checker internal checker;
    BaseERC721CheckerFactory internal factory;

    address public deployer = vm.addr(0x1);
    address public guarded = vm.addr(0x2);
    address public subject = vm.addr(0x3);
    address public notOwner = vm.addr(0x4);

    bytes public evidence = abi.encode(0);

    function setUp() public {
        vm.startPrank(deployer);

        nft = new NFT();

        factory = new BaseERC721CheckerFactory();

        vm.recordLogs();
        factory.deploy(address(nft));
        Vm.Log[] memory entries = vm.getRecordedLogs();
        address baseClone = address(uint160(uint256(entries[0].topics[1])));
        checker = BaseERC721Checker(baseClone);

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
        assertEq(checker.getAppendedBytes(), abi.encode(address(nft)));
    }

    function test_checker_whenTokenDoesNotExist_reverts() public {
        vm.startPrank(guarded);

        vm.expectRevert(abi.encodeWithSelector(IERC721Errors.ERC721NonexistentToken.selector, uint256(0)));
        checker.check(subject, evidence);

        vm.stopPrank();
    }

    function test_checker_whenCallerNotOwner_returnsFalse() public {
        vm.startPrank(guarded);

        nft.mint(subject);

        assert(!checker.check(notOwner, evidence));

        vm.stopPrank();
    }

    function test_checker_whenCallerIsOwner_succeeds() public {
        vm.startPrank(guarded);

        nft.mint(subject);

        assert(checker.check(subject, evidence));

        vm.stopPrank();
    }
}

contract BasePolicy is Test {
    event TargetSet(address indexed guarded);
    event Enforced(address indexed subject, address indexed guarded, bytes evidence);

    NFT internal nft;
    BaseERC721Checker internal checker;
    BaseERC721CheckerFactory internal checkerFactory;
    BaseERC721Policy internal policy;
    BaseERC721PolicyFactory internal policyFactory;

    address public deployer = vm.addr(0x1);
    address public guarded = vm.addr(0x2);
    address public subject = vm.addr(0x3);
    address public notOwner = vm.addr(0x4);

    bytes public evidence = abi.encode(0);

    function setUp() public virtual {
        vm.startPrank(deployer);

        nft = new NFT();

        checkerFactory = new BaseERC721CheckerFactory();
        policyFactory = new BaseERC721PolicyFactory();

        vm.recordLogs();
        checkerFactory.deploy(address(nft));
        Vm.Log[] memory entries = vm.getRecordedLogs();
        address checkerClone = address(uint160(uint256(entries[0].topics[1])));
        checker = BaseERC721Checker(checkerClone);

        vm.recordLogs();
        policyFactory.deploy(address(checker));
        entries = vm.getRecordedLogs();
        address policyClone = address(uint160(uint256(entries[0].topics[1])));
        policy = BaseERC721Policy(policyClone);

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
        assertEq(policy.trait(), "BaseERC721");
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

    function test_policy_enforce_whenCallerNotTarget_reverts() public {
        vm.startPrank(deployer);

        policy.setTarget(guarded);

        vm.stopPrank();

        vm.startPrank(subject);

        vm.expectRevert(abi.encodeWithSelector(IPolicy.TargetOnly.selector));
        policy.enforce(subject, evidence);

        vm.stopPrank();
    }

    function test_policy_enforce_whenTokenDoesNotExist_reverts() public {
        vm.startPrank(deployer);

        policy.setTarget(guarded);

        vm.stopPrank();

        vm.startPrank(guarded);

        vm.expectRevert(abi.encodeWithSelector(IERC721Errors.ERC721NonexistentToken.selector, uint256(0)));
        policy.enforce(subject, evidence);

        vm.stopPrank();
    }

    function test_policy_enforce_whenCheckFails_reverts() public {
        vm.startPrank(deployer);

        policy.setTarget(guarded);
        nft.mint(subject);

        vm.stopPrank();

        vm.startPrank(guarded);

        vm.expectRevert(abi.encodeWithSelector(IPolicy.UnsuccessfulCheck.selector));
        policy.enforce(notOwner, evidence);

        vm.stopPrank();
    }

    function test_policy_enforce_whenValid_succeeds() public {
        vm.startPrank(deployer);

        policy.setTarget(guarded);
        nft.mint(subject);

        vm.stopPrank();

        vm.startPrank(guarded);

        vm.expectEmit(true, true, true, true);
        emit Enforced(subject, guarded, evidence);

        policy.enforce(subject, evidence);

        vm.stopPrank();
    }
}

contract Voting is Test {
    event Registered(address voter);
    event Voted(address voter, uint8 option);

    NFT internal nft;
    BaseERC721Checker internal checker;
    BaseERC721CheckerFactory internal checkerFactory;
    BaseERC721Policy internal policy;
    BaseERC721PolicyFactory internal policyFactory;
    BaseVoting internal voting;

    address public deployer = vm.addr(0x1);
    address public subject = vm.addr(0x2);
    address public notOwner = vm.addr(0x3);

    function setUp() public virtual {
        vm.startPrank(deployer);

        nft = new NFT();

        checkerFactory = new BaseERC721CheckerFactory();
        policyFactory = new BaseERC721PolicyFactory();

        vm.recordLogs();
        checkerFactory.deploy(address(nft));
        Vm.Log[] memory entries = vm.getRecordedLogs();
        address checkerClone = address(uint160(uint256(entries[0].topics[1])));
        checker = BaseERC721Checker(checkerClone);

        vm.recordLogs();
        policyFactory.deploy(address(checker));
        entries = vm.getRecordedLogs();
        address policyClone = address(uint160(uint256(entries[0].topics[1])));
        policy = BaseERC721Policy(policyClone);

        voting = new BaseVoting(policy);

        vm.stopPrank();
    }

    function test_voting_deployed() public view {
        assertEq(address(voting.POLICY()), address(policy));
        assertEq(voting.hasVoted(subject), false);
        assertEq(voting.registered(subject), false);
    }

    function test_register_whenCallerNotTarget_reverts() public {
        vm.startPrank(deployer);

        policy.setTarget(deployer);
        nft.mint(subject);

        vm.stopPrank();

        vm.startPrank(notOwner);

        vm.expectRevert(abi.encodeWithSelector(IPolicy.TargetOnly.selector));
        voting.register(0);

        vm.stopPrank();
    }

    function test_register_whenTokenDoesNotExist_reverts() public {
        vm.startPrank(deployer);

        policy.setTarget(address(voting));
        nft.mint(subject);

        vm.stopPrank();

        vm.startPrank(subject);

        vm.expectRevert(abi.encodeWithSelector(IERC721Errors.ERC721NonexistentToken.selector, uint256(1)));
        voting.register(1);

        vm.stopPrank();
    }

    function test_register_whenCheckFails_reverts() public {
        vm.startPrank(deployer);

        policy.setTarget(address(voting));
        nft.mint(subject);

        vm.stopPrank();

        vm.startPrank(notOwner);

        vm.expectRevert(abi.encodeWithSelector(IPolicy.UnsuccessfulCheck.selector));
        voting.register(0);

        vm.stopPrank();
    }

    function test_register_whenValid_succeeds() public {
        vm.startPrank(deployer);

        policy.setTarget(address(voting));
        nft.mint(subject);

        vm.stopPrank();

        vm.startPrank(subject);

        vm.expectEmit(true, true, true, true);
        emit Registered(subject);

        voting.register(0);

        vm.stopPrank();
    }

    function test_vote_whenNotRegistered_reverts() public {
        vm.startPrank(deployer);

        policy.setTarget(address(voting));
        nft.mint(subject);

        vm.stopPrank();

        vm.startPrank(subject);

        vm.expectRevert(abi.encodeWithSelector(BaseVoting.NotRegistered.selector));
        voting.vote(0);

        vm.stopPrank();
    }

    function test_vote_whenInvalidOption_reverts() public {
        vm.startPrank(deployer);

        policy.setTarget(address(voting));
        nft.mint(subject);

        vm.stopPrank();

        vm.startPrank(subject);
        voting.register(0);

        vm.expectRevert(abi.encodeWithSelector(BaseVoting.InvalidOption.selector));
        voting.vote(3);

        vm.stopPrank();
    }

    function test_vote_whenValid_succeeds() public {
        vm.startPrank(deployer);

        policy.setTarget(address(voting));
        nft.mint(subject);

        vm.stopPrank();

        vm.startPrank(subject);
        voting.register(0);

        assertEq(voting.registered(subject), true);

        vm.expectEmit(true, true, true, true);
        emit Voted(subject, 0);

        voting.vote(0);

        assertEq(voting.hasVoted(subject), true);

        vm.stopPrank();
    }

    function test_vote_whenAlreadyVoted_reverts() public {
        vm.startPrank(deployer);

        policy.setTarget(address(voting));
        nft.mint(subject);

        vm.stopPrank();

        vm.startPrank(subject);

        voting.register(0);
        voting.vote(0);

        vm.expectRevert(abi.encodeWithSelector(BaseVoting.AlreadyVoted.selector));
        voting.vote(0);

        vm.stopPrank();
    }
}
