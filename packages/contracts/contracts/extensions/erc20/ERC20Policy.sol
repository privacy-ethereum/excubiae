// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

import { BasePolicy } from "../../policy/BasePolicy.sol";

/// @title ERC20Policy
/// @notice A policy which allows anyone with a token balance > threshold to sign up.
contract ERC20Policy is BasePolicy {
    /// @notice Store the addreses that have been enforced
    mapping(address => bool) public enforcedUsers;

    /// @notice Create a new instance of ERC20VotesPolicy
    // solhint-disable-next-line no-empty-blocks
    constructor() payable { }

    /// @notice Enforce a user based on their token balance
    /// @dev Throw if the token balance is not valid or just complete silently
    /// @param subject The user's Ethereum address.
    function _enforce(address subject, bytes calldata evidence) internal override {
        if (enforcedUsers[subject]) {
            revert AlreadyEnforced();
        }

        enforcedUsers[subject] = true;

        super._enforce(subject, evidence);
    }

    /// @notice Get the trait of the Policy
    /// @return The type of the Policy
    function trait() public pure override returns (string memory) {
        return "ERC20";
    }
}
