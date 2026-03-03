// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

import {Factory} from "../../proxy/Factory.sol";
import {IPolicyFactory} from "../../interfaces/IPolicyFactory.sol";
import {HatsPolicy} from "./HatsPolicy.sol";

/// @title HatsPolicyFactory
/// @notice Factory contract for deploying minimal proxy instances of HatsPolicy.
/// @dev Simplifies deployment of HatsPolicy clones with appended configuration data.
contract HatsPolicyFactory is Factory, IPolicyFactory {
    /// @notice Initializes the factory with the HatsPolicy implementation.
    constructor() Factory(address(new HatsPolicy())) {}

    /// @notice Deploys a new HatsPolicy clone with the specified checker address.
    /// @dev Encodes the checker address and caller as configuration data for the clone.
    /// @param checkerAddress Address of the checker to use for validation.
    /// @return clone The address of the newly deployed HatsPolicy clone.
    function deploy(address checkerAddress) public returns (address clone) {
        bytes memory data = abi.encode(msg.sender, checkerAddress);

        clone = super._deploy(data);

        HatsPolicy(clone).initialize();
    }
}
