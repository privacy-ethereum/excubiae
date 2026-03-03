// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

import { IPolicy } from "./IPolicy.sol";
import { Check } from "./IAdvancedChecker.sol";

/// @title IAdvancedPolicy
/// @notice Extends IPolicy with support for multi-phase validation checks (pre, main, post).
/// @dev Adds granular error reporting and event logging for advanced enforcement scenarios.
interface IAdvancedPolicy is IPolicy {
    /// @notice Error thrown when multiple main checks are attempted but not allowed.
    error MainCheckAlreadyEnforced();

    /// @notice Error thrown when a main check is attempted without a prior pre-check.
    error PreCheckNotEnforced();

    /// @notice Error thrown when a post-check is attempted without a prior main check.
    error MainCheckNotEnforced();

    /// @notice Error thrown when a pre-check is attempted while pre-checks are skipped.
    error CannotPreCheckWhenSkipped();

    /// @notice Error thrown when a post-check is attempted while post-checks are skipped.
    error CannotPostCheckWhenSkipped();

    /// @notice Emitted when a subject successfully passes a validation check.
    /// @param subject Address that passed the validation.
    /// @param guarded Address of the protected contract.
    /// @param evidence Custom validation data.
    /// @param checkType The type of check performed (PRE, MAIN, POST).
    event Enforced(address indexed subject, address indexed guarded, bytes evidence, Check checkType);

    /// @notice Enforces a specific phase of the policy check on a given subject.
    /// @dev Delegates validation logic to the corresponding phase's check method.
    /// @param subject Address to validate.
    /// @param evidence Custom validation data.
    /// @param checkType The type of check performed (PRE, MAIN, POST).
    function enforce(address subject, bytes calldata evidence, Check checkType) external;
}
