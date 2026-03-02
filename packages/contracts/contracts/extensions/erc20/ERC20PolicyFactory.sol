// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

import {Factory} from "../../proxy/Factory.sol";
import {IPolicyFactory} from "../../interfaces/IPolicyFactory.sol";
import {ERC20Policy} from "./ERC20Policy.sol";

/// @title ERC20PolicyFactory
/// @notice Factory contract for deploying minimal proxy instances of ERC20Policy.
/// @dev Simplifies deployment of ERC20Policy clones with appended configuration data.
contract ERC20PolicyFactory is Factory, IPolicyFactory {
    /// @notice Initializes the factory with the ERC20Policy implementation.
    constructor() Factory(address(new ERC20Policy())) {}

    /// @notice Deploys a new ERC20Policy clone with the specified checker address.
    /// @dev Encodes the checker address and caller as configuration data for the clone.
    /// @param _checkerAddress Address of the checker to use for validation.
    /// @return clone The address of the newly deployed ERC20Policy clone.
    function deploy(address _checkerAddress) public returns (address clone) {
        bytes memory data = abi.encode(msg.sender, _checkerAddress);

        clone = super._deploy(data);

        ERC20Policy(clone).initialize();
    }
}
