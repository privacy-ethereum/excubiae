// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

import {Factory} from "../../proxy/Factory.sol";
import {IPolicyFactory} from "../../interfaces/IPolicyFactory.sol";
import {EASPolicy} from "./EASPolicy.sol";

/// @title EASPolicyFactory
/// @notice Factory contract for deploying minimal proxy instances of EASPolicy.
/// @dev Simplifies deployment of EASPolicy clones with appended configuration data.
contract EASPolicyFactory is Factory, IPolicyFactory {
    /// @notice Initializes the factory with the EASPolicy implementation.
    constructor() Factory(address(new EASPolicy())) {}

    /// @notice Deploys a new EASPolicy clone with the specified checker address.
    /// @dev Encodes the checker address and caller as configuration data for the clone.
    /// @param checkerAddress Address of the checker to use for validation.
    /// @return clone The address of the newly deployed EASPolicy clone.
    function deploy(address checkerAddress) public returns (address clone) {
        bytes memory data = abi.encode(msg.sender, checkerAddress);

        clone = super._deploy(data);

        EASPolicy(clone).initialize();
    }
}
