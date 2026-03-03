// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

import { IBaseChecker } from "../interfaces/IBaseChecker.sol";
import { Clone } from "../proxy/Clone.sol";

/// @title BaseChecker
/// @notice Abstract base contract for implementing validation checks.
/// @dev This contract provides a standardized interface for validation logic, delegating
///      actual implementation to the internal `_check` method. It is clone-compatible.
abstract contract BaseChecker is Clone, IBaseChecker {
    /// @notice Validates a subject's evidence.
    /// @dev External view function that calls the `_check` method, allowing derived contracts
    ///      to implement custom validation logic.
    /// @param subject The address to validate.
    /// @param evidence Custom validation data.
    /// @return checked Boolean indicating whether the validation passed.
    function check(address subject, bytes calldata evidence) external view override returns (bool checked) {
        return _check(subject, evidence);
    }

    /// @notice Internal validation logic implementation.
    /// @dev Must be overridden by derived contracts to define custom validation rules.
    /// @param subject The address to validate.
    /// @param evidence Custom validation data.
    /// @return checked Boolean indicating whether the validation passed.
    function _check(address subject, bytes calldata evidence) internal view virtual returns (bool checked) { }
}
