// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

import {BasePolicy} from "../../policy/BasePolicy.sol";

/// @title EASPolicy
/// @notice A policy contract enforcing EAS validation.
/// Only if they've received an attestation of a specific schema from a trusted attester
contract EASPolicy is BasePolicy {
    // a mapping of addresses that have already been enforced
    mapping(address => bool) public enforcedAddresses;

    /// @notice Deploy an instance of EASPolicy
    // solhint-disable-next-line no-empty-blocks
    constructor() payable {}

    /// @notice Enforce a user based on their attestation
    /// @dev Throw if the attestation is not valid or just complete silently
    /// @param subject The user's Ethereum address.
    /// @param evidence The ABI-encoded schemaId as a uint256. It is passed directly to the BasePolicy._enforce.
    function _enforce(address subject, bytes calldata evidence) internal override {
        if (enforcedAddresses[subject]) {
            revert AlreadyEnforced();
        }

        enforcedAddresses[subject] = true;

        super._enforce(subject, evidence);
    }

    /// @notice Get the trait of the Policy
    /// @return The type of the Policy
    function trait() public pure override returns (string memory) {
        return "EAS";
    }
}
