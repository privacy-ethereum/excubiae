// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

import { Factory } from "../../proxy/Factory.sol";
import { IPolicyFactory } from "../../interfaces/IPolicyFactory.sol";
import { SemaphorePolicy } from "./SemaphorePolicy.sol";

/// @title SemaphorePolicyFactory
/// @notice Factory contract for deploying minimal proxy instances of SemaphorePolicy.
/// @dev Simplifies deployment of SemaphorePolicy clones with appended configuration data.
contract SemaphorePolicyFactory is Factory, IPolicyFactory {
    /// @notice Initializes the factory with the SemaphorePolicy implementation.
    constructor() Factory(address(new SemaphorePolicy())) { }

    /// @notice Deploys a new SemaphorePolicy clone with the specified checker address.
    /// @dev Encodes the checker address and caller as configuration data for the clone.
    /// @param checkerAddress Address of the checker to use for validation.
    /// @return clone The address of the newly deployed SemaphorePolicy clone.
    function deploy(address checkerAddress) public returns (address clone) {
        bytes memory data = abi.encode(msg.sender, checkerAddress);

        clone = super._deploy(data);

        SemaphorePolicy(clone).initialize();
    }
}
