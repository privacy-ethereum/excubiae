// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

import { BaseERC721Policy } from "./BaseERC721Policy.sol";

/// @title BaseVoting
/// @notice Simple NFT-based voting system.
/// @dev Implements a basic two-phase voting system (registration and voting) with access control enforced by NFTs.
contract BaseVoting {
    /// @notice Emitted when a voter successfully registers.
    /// @param voter Address of the registered voter.
    event Registered(address voter);

    /// @notice Emitted when a voter successfully casts a vote.
    /// @param voter Address of the voter.
    /// @param option The option the voter chose.
    event Voted(address voter, uint8 option);

    /// @notice Error thrown when a user attempts to vote without registering.
    error NotRegistered();

    /// @notice Error thrown when a user attempts to vote more than once.
    error AlreadyVoted();

    /// @notice Error thrown when a user attempts to vote with an invalid option.
    error InvalidOption();

    /// @notice Policy contract enforcing NFT-based registration.
    BaseERC721Policy public immutable POLICY;

    /// @dev Tracks whether an address has been registered.
    mapping(address => bool) public registered;

    /// @dev Tracks whether an address has voted.
    mapping(address => bool) public hasVoted;

    /// @notice Initializes the voting system with a specific policy contract.
    /// @param _policy Address of the policy contract enforcing access control.
    constructor(BaseERC721Policy _policy) {
        POLICY = _policy;
    }

    /// @notice Registers a voter based on NFT ownership.
    /// @dev Enforces ownership validation via the policy contract.
    /// @param tokenId Token ID of the NFT used for validation.
    function register(uint256 tokenId) external {
        // Enforce NFT ownership validation.
        POLICY.enforce(msg.sender, abi.encode(tokenId));

        // Track enforcement.
        registered[msg.sender] = true;

        emit Registered(msg.sender);
    }

    /// @notice Casts a vote after successful registration.
    /// @dev Validates voter registration and option validity before recording the vote.
    /// @param option The chosen voting option (0 or 1).
    function vote(uint8 option) external {
        // Check registration and voting status.
        if (!registered[msg.sender]) revert NotRegistered();
        if (hasVoted[msg.sender]) revert AlreadyVoted();
        if (option >= 2) revert InvalidOption();

        // Record the vote.
        hasVoted[msg.sender] = true;

        emit Voted(msg.sender, option);
    }
}
