// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

import {BasePolicy} from "../../policy/BasePolicy.sol";

/// @title FreeForAllPolicy
/// @notice A policy which allows anyone to sign up, but only once per address.
contract FreeForAllPolicy is BasePolicy {
    /// @notice Store the addreses that have been enforced
    mapping(address => bool) public enforcedUsers;

    /// @notice Create a new instance of FreeForAllPolicy
    // solhint-disable-next-line no-empty-blocks
    constructor() payable {}

    /// @notice Enforce a user so they can only be enforced once
    /// @param subject The user's Ethereum address.
    /// @param evidence The ABI-encoded evidence data.
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
        return "FreeForAll";
    }
}
