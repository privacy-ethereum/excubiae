// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

import { IClone } from "../interfaces/IClone.sol";
import { LibClone } from "solady/src/utils/LibClone.sol";

/// @title Clone
/// @notice Abstract base contract for creating cloneable contracts with initialization logic.
/// @dev Provides utilities for managing clone initialization and retrieving appended arguments.
abstract contract Clone is IClone {
    /// @notice Tracks whether the clone has been initialized.
    /// @dev Prevents re-initialization through the `_initialize` function.
    bool public initialized;

    /// @notice Initializes the clone.
    /// @dev Calls the internal `_initialize` function to set up the clone.
    /// Reverts if the clone is already initialized.
    function initialize() external {
        _initialize();
    }

    /// @notice Retrieves appended arguments from the clone.
    /// @dev Leverages `LibClone` to extract arguments from the clone's runtime bytecode.
    /// @return appendedBytes The appended bytes extracted from the clone.
    function getAppendedBytes() external view returns (bytes memory appendedBytes) {
        return _getAppendedBytes();
    }

    /// @notice Internal function to initialize the clone.
    /// @dev Must be overridden by derived contracts to implement custom initialization logic.
    /// Reverts if the clone has already been initialized.
    function _initialize() internal virtual {
        if (initialized) revert AlreadyInitialized();
        initialized = true;
    }

    /// @notice Internal function to retrieve appended arguments from the clone.
    /// @dev Uses `LibClone` utility to extract the arguments.
    /// @return appendedBytes The appended bytes extracted from the clone.
    function _getAppendedBytes() internal view virtual returns (bytes memory appendedBytes) {
        return LibClone.argsOnClone(address(this));
    }
}
