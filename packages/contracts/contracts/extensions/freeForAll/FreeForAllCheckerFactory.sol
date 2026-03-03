// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

import { Factory } from "../../proxy/Factory.sol";
import { FreeForAllChecker } from "./FreeForAllChecker.sol";

/// @title FreeForAllCheckerFactory
/// @notice Factory contract for deploying minimal proxy instances of FreeForAllChecker.
/// @dev Simplifies deployment of FreeForAllChecker clones with appended configuration data.
contract FreeForAllCheckerFactory is Factory {
    /// @notice Initializes the factory with the FreeForAllChecker implementation.
    constructor() Factory(address(new FreeForAllChecker())) { }

    /// @notice Deploys a new FreeForAllChecker clone.
    /// @return clone The address of the newly deployed FreeForAllChecker clone.
    function deploy() public returns (address clone) {
        bytes memory data = abi.encode();

        clone = super._deploy(data);

        FreeForAllChecker(clone).initialize();
    }
}
