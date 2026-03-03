// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

import { IAdvancedChecker, Check, CheckStatus } from "../interfaces/IAdvancedChecker.sol";
import { Clone } from "../proxy/Clone.sol";

/// @title AdvancedChecker
/// @notice Abstract contract for multi-phase validation (PRE, MAIN, POST).
/// @dev Implements advanced validation by routing checks to appropriate phases.
///      This is intended to be extended for complex validation systems.
abstract contract AdvancedChecker is Clone, IAdvancedChecker {
    /// @notice Validates a subject's evidence for a specific check phase.
    /// @dev External entry point for validation checks, delegating logic to `_check`.
    /// @param subject The address to validate.
    /// @param evidence Custom validation data.
    /// @param checkType The phase of validation to execute (PRE, MAIN, POST).
    /// @return checked Boolean indicating whether the validation passed.
    function check(
        address subject,
        bytes calldata evidence,
        Check checkType
    )
        external
        view
        override
        returns (bool checked)
    {
        return _check(subject, evidence, checkType);
    }

    /// @notice Core validation logic dispatcher.
    /// @dev Routes validation calls to specific phase methods (_checkPre, _checkMain, _checkPost).
    /// @param subject The address to validate.
    /// @param evidence Custom validation data.
    /// @param checkType The phase of validation to execute.
    /// @return checked Boolean indicating whether the validation passed.
    function _check(address subject, bytes calldata evidence, Check checkType) internal view returns (bool checked) {
        if (checkType == Check.PRE) {
            return _checkPre(subject, evidence);
        }

        if (checkType == Check.POST) {
            return _checkPost(subject, evidence);
        }

        return _checkMain(subject, evidence);
    }

    /// @notice Pre-condition validation logic.
    /// @dev Derived contracts should override this to implement pre-check validation.
    /// @param subject The address to validate.
    /// @param evidence Custom validation data.
    /// @return checked Boolean indicating whether the validation passed.
    function _checkPre(address subject, bytes calldata evidence) internal view virtual returns (bool checked) { }

    /// @notice Main validation logic.
    /// @dev Derived contracts should override this to implement main check validation.
    /// @param subject The address to validate.
    /// @param evidence Custom validation data.
    /// @return checked Boolean indicating whether the validation passed.
    function _checkMain(address subject, bytes calldata evidence) internal view virtual returns (bool checked) { }

    /// @notice Post-condition validation logic.
    /// @dev Derived contracts should override this to implement post-check validation.
    /// @param subject The address to validate.
    /// @param evidence Custom validation data.
    /// @return checked Boolean indicating whether the validation passed.
    function _checkPost(address subject, bytes calldata evidence) internal view virtual returns (bool checked) { }
}
