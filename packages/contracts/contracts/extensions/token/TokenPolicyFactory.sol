// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

import {Factory} from "../../proxy/Factory.sol";
import {IPolicyFactory} from "../../interfaces/IPolicyFactory.sol";
import {TokenPolicy} from "./TokenPolicy.sol";

/// @title TokenPolicyFactory
/// @notice Factory contract for deploying minimal proxy instances of TokenPolicy.
/// @dev Simplifies deployment of TokenPolicy clones with appended configuration data.
contract TokenPolicyFactory is Factory, IPolicyFactory {
    /// @notice Initializes the factory with the TokenPolicy implementation.
    constructor() Factory(address(new TokenPolicy())) {}

    /// @notice Deploys a new TokenPolicy clone with the specified checker address.
    /// @dev Encodes the checker address and caller as configuration data for the clone.
    /// @param checkerAddress Address of the checker to use for validation.
    /// @return clone The address of the newly deployed TokenPolicy clone.
    function deploy(address checkerAddress) public returns (address clone) {
        bytes memory data = abi.encode(msg.sender, checkerAddress);

        clone = super._deploy(data);

        TokenPolicy(clone).initialize();
    }
}
