// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

import { IPolicy } from "./IPolicy.sol";

/// @title IBasePolicy
/// @notice Extends IPolicy with basic validation and enforcement capabilities.
/// @dev Adds event logging and a method to enforce policy checks.
interface IBasePolicy is IPolicy {
    /// @notice Emitted when a subject successfully passes a policy enforcement check.
    /// @param subject Address that passed the validation.
    /// @param guarded Address of the protected contract.
    /// @param evidence Custom validation data.
    event Enforced(address indexed subject, address indexed guarded, bytes evidence);

    /// @notice Enforces a validation check on a given subject.
    /// @dev This method ensures that the provided subject meets the policy's criteria.
    /// @param subject Address to validate.
    /// @param evidence Custom validation data.
    function enforce(address subject, bytes calldata evidence) external;
}
