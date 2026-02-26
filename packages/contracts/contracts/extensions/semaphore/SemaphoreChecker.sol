// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

import {BaseChecker} from "../../checker/BaseChecker.sol";
import {ISemaphore} from "./ISemaphore.sol";

/// @title SemaphoreChecker
/// @notice Implements proof of membership validation using Semaphore.
/// @dev Inherits from BaseChecker to extend the validation logic.
/// Ensures unique identity usage through nullifier tracking.
/// This is because we store the nullifier which is
/// hash(secret, groupId). The prover address is bound in the proof message field.
contract SemaphoreChecker is BaseChecker {
    /// @notice Address of the Semaphore contract used for proof verification.
    ISemaphore public semaphore;

    /// @notice Unique identifier for the Semaphore group.
    /// @dev Proofs are validated against this specific group ID.
    uint256 public groupId;

    /// @notice custom errors
    error InvalidProver();
    error InvalidGroup();
    error InvalidProof();

    /// @notice Initializes the SemaphoreChecker with the provided Semaphore contract address and group ID.
    /// @dev Decodes initialization parameters from appended bytes for clone deployments.
    function _initialize() internal override {
        super._initialize();

        bytes memory data = _getAppendedBytes();
        (address _semaphore, uint256 _groupId) = abi.decode(data, (address, uint256));

        semaphore = ISemaphore(_semaphore);
        groupId = _groupId;
    }

    /// @notice Verifies if the given subject is a valid member of the Semaphore group.
    /// @dev Decodes the evidence to extract the Semaphore proof and validates the subject's membership.
    /// @param subject The address of the user whose membership is being verified.
    /// @param evidence Encoded Semaphore proof containing membership verification details.
    /// @return Boolean indicating the success or failure of the membership verification.
    function _check(address subject, bytes calldata evidence) internal view override returns (bool) {
        super._check(subject, evidence);

        ISemaphore.SemaphoreProof memory proof = abi.decode(evidence, (ISemaphore.SemaphoreProof));

        // The proof scope is the group ID; the prover address is bound in the message field.
        uint256 _scope = proof.scope;

        if (_scope != groupId) {
            revert InvalidGroup();
        }

        // Extract the subject's address from the message field.
        address _prover = address(uint160(proof.message));

        if (_prover != subject) {
            revert InvalidProver();
        }

        if (!semaphore.verifyProof(_scope, proof)) {
            revert InvalidProof();
        }

        return true;
    }
}
