// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

import { IBasePolicy } from "../interfaces/IBasePolicy.sol";
import { Policy } from "./Policy.sol";
import { BaseChecker } from "../checker/BaseChecker.sol";

/// @title BasePolicy
/// @notice Abstract base contract for implementing custom policies using a BaseChecker.
/// @dev Extends Policy and provides enforcement logic using a BaseChecker instance.
abstract contract BasePolicy is Policy, IBasePolicy {
    /// @notice Reference to the BaseChecker contract used for validation.
    BaseChecker public BASE_CHECKER;

    /// @notice Initializes the contract with appended bytes data for configuration.
    /// @dev Decodes BaseChecker address and sets the owner.
    function _initialize() internal virtual override {
        super._initialize();

        bytes memory data = _getAppendedBytes();
        (address sender, address baseCheckerAddr) = abi.decode(data, (address, address));

        _transferOwnership(sender);

        BASE_CHECKER = BaseChecker(baseCheckerAddr);
    }

    /// @notice Enforces a policy check for a subject.
    /// @dev Uses the BaseChecker for validation logic. Only callable by the guarded contract.
    /// @param subject Address to enforce the policy on.
    /// @param evidence Custom validation data.
    function enforce(address subject, bytes calldata evidence) external override onlyTarget {
        _enforce(subject, evidence);
    }

    /// @notice Internal logic for enforcing policy checks.
    /// @param subject Address to enforce the policy on.
    /// @param evidence Custom validation data.
    function _enforce(address subject, bytes calldata evidence) internal virtual {
        if (!BASE_CHECKER.check(subject, evidence)) revert UnsuccessfulCheck();

        emit Enforced(subject, guarded, evidence);
    }
}
