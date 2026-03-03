// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

import { AdvancedPolicy } from "../../../policy/AdvancedPolicy.sol";
import { Check } from "../../../interfaces/IAdvancedPolicy.sol";

/// @title AdvancedVoting
/// @notice Multi-phase governance system with NFT-based validation.
/// @dev Combines pre, main, and post phases for registration, voting, and eligibility verification.
contract AdvancedVoting {
    /// @notice Emitted when a voter registers successfully.
    /// @param voter Address of the voter who registered.
    event Registered(address voter);

    /// @notice Emitted when a vote is cast successfully.
    /// @param voter Address of the voter who cast their vote.
    /// @param option The chosen voting option (0 or 1).
    event Voted(address voter, uint8 option);

    /// @notice Emitted when a voter is deemed eligible.
    /// @param voter Address of the voter who met eligibility criteria.
    event Eligible(address voter);

    /// @notice Error thrown when a user attempts an action without registering first.
    error NotRegistered();

    /// @notice Error thrown when a user attempts to verify eligibility without voting.
    error NotVoted();

    /// @notice Error thrown when a user tries to verify eligibility more than once.
    error AlreadyEligible();

    /// @notice Error thrown when an invalid voting option is provided.
    error InvalidOption();

    /// @notice Error thrown when a user does not meet the eligibility criteria.
    error NotEligible();

    /// @notice Reference to the policy contract enforcing multi-phase validation.
    AdvancedPolicy public immutable POLICY;

    /// @dev Tracks whether an address has been registered.
    mapping(address => bool) public registered;

    /// @dev Tracks whether an address has voted.
    mapping(address => bool) public hasVoted;

    /// @dev Tracks whether an address has been marked as eligible.
    mapping(address => bool) public isEligible;

    /// @notice Constructor to set the policy contract.
    /// @param _policy Address of the AdvancedPolicy contract to use for validation.
    constructor(AdvancedPolicy _policy) {
        POLICY = _policy;
    }

    /// @notice Registers a user for voting by validating their NFT ownership.
    /// @dev Enforces the pre-check phase using the AdvancedPolicy contract.
    /// @param tokenId The ID of the NFT used to verify registration eligibility.
    function register(uint256 tokenId) external {
        // Enforce the pre-check phase using the provided policy.
        POLICY.enforce(msg.sender, abi.encode(tokenId), Check.PRE);

        // Track enforcement.
        registered[msg.sender] = true;

        // Emit an event to log the registration.
        emit Registered(msg.sender);
    }

    /// @notice Allows a registered user to cast their vote.
    /// @dev Enforces the main-check phase and updates the vote count.
    /// @param option The chosen voting option (0 or 1).
    function vote(uint8 option) external {
        // Ensure the user has registered before voting.
        if (!registered[msg.sender]) revert NotRegistered();

        // Validate that the voting option is within the allowed range.
        if (option >= 2) revert InvalidOption();

        // Enforce the main-check phase using the policy.
        POLICY.enforce(msg.sender, abi.encode(option), Check.MAIN);

        // Record the vote.
        hasVoted[msg.sender] = true;

        // Emit an event to log the voting action.
        emit Voted(msg.sender, option);
    }

    /// @notice Verifies a user's eligibility after voting has concluded.
    /// @dev Enforces the post-check phase to ensure eligibility criteria are met.
    function eligible() external {
        // Ensure the user has completed the registration phase.
        if (!registered[msg.sender]) revert NotRegistered();

        // Ensure the user has cast at least one vote.
        if (!hasVoted[msg.sender]) revert NotVoted();

        // Ensure the user has not already been marked as eligible.
        if (isEligible[msg.sender]) revert AlreadyEligible();

        // Enforce the post-check phase using the policy.
        POLICY.enforce(msg.sender, abi.encode(), Check.POST);

        // Record eligibility.
        isEligible[msg.sender] = true;

        // Emit an event to log the eligibility status.
        emit Eligible(msg.sender);
    }
}
