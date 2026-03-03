// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

import { IAdvancedPolicy, Check } from "../interfaces/IAdvancedPolicy.sol";
import { AdvancedChecker } from "../checker/AdvancedChecker.sol";
import { Policy } from "./Policy.sol";

/// @title AdvancedPolicy
/// @notice Implements multi-stage policy checks with pre, main, and post validation stages.
/// @dev Extends Policy and provides advanced enforcement logic with an AdvancedChecker.
abstract contract AdvancedPolicy is IAdvancedPolicy, Policy {
    /// @notice Reference to the AdvancedChecker contract used for validation.
    AdvancedChecker public ADVANCED_CHECKER;

    /// @notice Controls whether pre-condition checks are required.
    bool public SKIP_PRE;

    /// @notice Controls whether post-condition checks are required.
    bool public SKIP_POST;

    /// @notice Initializes the contract with appended bytes data for configuration.
    /// @dev Decodes AdvancedChecker address and sets the owner.
    function _initialize() internal virtual override {
        super._initialize();

        bytes memory data = _getAppendedBytes();
        (address sender, address advCheckerAddr, bool skipPre, bool skipPost) =
            abi.decode(data, (address, address, bool, bool));

        _transferOwnership(sender);

        ADVANCED_CHECKER = AdvancedChecker(advCheckerAddr);
        SKIP_PRE = skipPre;
        SKIP_POST = skipPost;
    }

    /// @notice Enforces a multi-stage policy check.
    /// @dev Handles pre, main, and post validation stages. Only callable by the guarded contract.
    /// @param subject Address to enforce the policy on.
    /// @param evidence Custom validation data.
    /// @param checkType The type of check performed (PRE, MAIN, POST).
    function enforce(address subject, bytes calldata evidence, Check checkType) external override onlyTarget {
        _enforce(subject, evidence, checkType);
    }

    /// @notice Internal implementation of multi-stage enforcement logic.
    /// @param subject Address to enforce the policy on.
    /// @param evidence Custom validation data.
    /// @param checkType The type of check performed (PRE, MAIN, POST).
    function _enforce(address subject, bytes calldata evidence, Check checkType) internal virtual {
        if (checkType == Check.PRE) {
            if (SKIP_PRE) revert CannotPreCheckWhenSkipped();
        } else if (checkType == Check.POST) {
            if (SKIP_POST) revert CannotPostCheckWhenSkipped();
        }

        if (!ADVANCED_CHECKER.check(subject, evidence, checkType)) revert UnsuccessfulCheck();

        emit Enforced(subject, guarded, evidence, checkType);
    }
}
