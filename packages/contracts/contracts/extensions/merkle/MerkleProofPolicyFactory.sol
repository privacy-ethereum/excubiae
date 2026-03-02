// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

import {Factory} from "../../proxy/Factory.sol";
import {IPolicyFactory} from "../../interfaces/IPolicyFactory.sol";
import {MerkleProofPolicy} from "./MerkleProofPolicy.sol";

/// @title MerkleProofPolicyFactory
/// @notice Factory contract for deploying minimal proxy instances of MerkleProofPolicy.
/// @dev Simplifies deployment of MerkleProofPolicy clones with appended configuration data.
contract MerkleProofPolicyFactory is Factory, IPolicyFactory {
    /// @notice Initializes the factory with the MerkleProofPolicy implementation.
    constructor() Factory(address(new MerkleProofPolicy())) {}

    /// @notice Deploys a new MerkleProofPolicy clone with the specified checker address.
    /// @dev Encodes the checker address and caller as configuration data for the clone.
    /// @param checkerAddress Address of the checker to use for validation.
    /// @return clone The address of the newly deployed MerkleProofPolicy clone.
    function deploy(address checkerAddress) public returns (address clone) {
        bytes memory data = abi.encode(msg.sender, checkerAddress);

        clone = super._deploy(data);

        MerkleProofPolicy(clone).initialize();
    }
}
