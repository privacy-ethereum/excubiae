// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

import { BasePolicy } from "../../policy/BasePolicy.sol";
import { IGitcoinPassportDecoder } from "./IGitcoinPassportDecoder.sol";

/// @title GitcoinPassportPolicy
/// @notice A policy contract enforcing gitcoin validation.
/// Only if they've received an attestation of a specific schema from a trusted attester
contract GitcoinPassportPolicy is BasePolicy {
    // a mapping of attestations that have already enforced
    mapping(address => bool) public enforcedUsers;

    /// @notice Deploy an instance of GitcoinPassportPolicy
    // solhint-disable-next-line no-empty-blocks
    constructor() payable { }

    /// @notice Enforce a user based on their attestation
    /// @dev Throw if the attestation is not valid or just complete silently
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
        return "GitcoinPassport";
    }
}
