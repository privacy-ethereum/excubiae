// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

import { BasePolicy } from "../../policy/BasePolicy.sol";

/// @title AnonAadhaarPolicy
/// @notice Policy contract enforcing Aadhaar validation.
/// Only if they can prove they are valid Aadhaar owners.
/// @dev Please note that once a identity is used to enforce, it cannot be used again.
/// This is because we store the nullifier of the proof.
contract AnonAadhaarPolicy is BasePolicy {
    /// @notice The enforced identities
    mapping(uint256 => bool) public enforcedAadhaars;

    /// @notice Create a new instance of AnonAadhaarPolicy
    // solhint-disable-next-line no-empty-blocks
    constructor() payable { }

    /// @notice Enforce a user if they can prove anonAadhaar proof
    /// @dev Throw if the proof is not valid or just complete silently
    /// @param subject The address of the entity being validated.
    /// @param evidence The ABI-encoded data containing nullifierSeed, nullifier, timestamp, signal, revealArray,
    /// and groth16Proof.
    function _enforce(address subject, bytes calldata evidence) internal override {
        // decode the argument
        (, uint256 nullifier,,,,) = abi.decode(evidence, (uint256, uint256, uint256, uint256, uint256[4], uint256[8]));

        if (enforcedAadhaars[nullifier]) {
            revert AlreadyEnforced();
        }

        enforcedAadhaars[nullifier] = true;

        super._enforce(subject, evidence);
    }

    /// @notice Get the trait of the Policy
    /// @return The type of the Policy
    function trait() public pure override returns (string memory) {
        return "AnonAadhaar";
    }
}
