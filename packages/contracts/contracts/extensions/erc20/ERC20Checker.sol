// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

import { IERC20 } from "@openzeppelin/contracts/token/ERC20/IERC20.sol";

import { BaseChecker } from "../../checker/BaseChecker.sol";

/// @title ERC20Checker
/// @notice ERC20 validator.
/// @dev Extends BaseChecker to implement ERC20 validation logic.
contract ERC20Checker is BaseChecker {
    /// @notice the token to check
    IERC20 public token;

    /// @notice the threshold
    uint256 public threshold;

    /// @notice the balance is too low
    error BalanceTooLow();

    /// @notice Initializes the contract.
    function _initialize() internal override {
        super._initialize();

        bytes memory data = _getAppendedBytes();
        (address _token, uint256 _threshold) = abi.decode(data, (address, uint256));

        token = IERC20(_token);
        threshold = _threshold;
    }

    /// @notice Returns true for everycall.
    /// @param subject Address to validate.
    /// @param evidence Encoded data used for validation.
    /// @return Boolean indicating whether the subject passes the check.
    function _check(address subject, bytes calldata evidence) internal view override returns (bool) {
        super._check(subject, evidence);

        // get the token balance of the subject
        uint256 balance = token.balanceOf(subject);

        // check if the balance is enough
        if (balance <= threshold) {
            revert BalanceTooLow();
        }

        return true;
    }
}
