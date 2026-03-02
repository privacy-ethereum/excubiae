// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

import {Factory} from "../../proxy/Factory.sol";
import {IPolicyFactory} from "../../interfaces/IPolicyFactory.sol";
import {ERC20VotesPolicy} from "./ERC20VotesPolicy.sol";

/// @title ERC20VotesPolicyFactory
/// @notice Factory contract for deploying minimal proxy instances of ERC20VotesPolicy.
/// @dev Simplifies deployment of ERC20VotesPolicy clones with appended configuration data.
contract ERC20VotesPolicyFactory is Factory, IPolicyFactory {
    /// @notice Initializes the factory with the ERC20VotesPolicy implementation.
    constructor() Factory(address(new ERC20VotesPolicy())) {}

    /// @notice Deploys a new ERC20VotesPolicy clone with the specified checker address.
    /// @dev Encodes the checker address and caller as configuration data for the clone.
    /// @param _checkerAddress Address of the checker to use for validation.
    /// @return clone The address of the newly deployed ERC20VotesPolicy clone.
    function deploy(address _checkerAddress) public returns (address clone) {
        bytes memory data = abi.encode(msg.sender, _checkerAddress);

        clone = super._deploy(data);

        ERC20VotesPolicy(clone).initialize();
    }
}
