// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

import { Factory } from "../../proxy/Factory.sol";
import { IPolicyFactory } from "../../interfaces/IPolicyFactory.sol";
import { AnonAadhaarPolicy } from "./AnonAadhaarPolicy.sol";

/// @title AnonAadhaarPolicyFactory
/// @notice Factory contract for deploying minimal proxy instances of AnonAadhaarPolicy.
/// @dev Simplifies deployment of AnonAadhaarPolicy clones with appended configuration data.
contract AnonAadhaarPolicyFactory is Factory, IPolicyFactory {
    /// @notice Initializes the factory with the AnonAadhaarPolicy implementation.
    constructor() Factory(address(new AnonAadhaarPolicy())) { }

    /// @notice Deploys a new AnonAadhaarPolicy clone with the specified checker address.
    /// @dev Encodes the checker address and caller as configuration data for the clone.
    /// @param checkerAddress Address of the checker to use for validation.
    /// @return clone The address of the newly deployed AnonAadhaarPolicy clone.
    function deploy(address checkerAddress) public returns (address clone) {
        bytes memory data = abi.encode(msg.sender, checkerAddress);

        clone = super._deploy(data);

        AnonAadhaarPolicy(clone).initialize();
    }
}
