// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

import { IBaseChecker } from "../../../interfaces/IBaseChecker.sol";

/// @title BaseCheckerMock
/// @notice Mock implementation of the IBaseChecker interface for testing purposes.
/// @dev Provides a dummy check function that always returns false.
contract BaseCheckerMock is IBaseChecker {
    /// @notice Mock check function that always returns false.
    /// @dev This function simulates a failed check for testing.
    /// @return Always returns false.
    function check(address, bytes calldata) external pure override returns (bool) {
        return false;
    }
}
