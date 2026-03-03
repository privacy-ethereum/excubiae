// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

import { BaseERC721Checker } from "./BaseERC721Checker.sol";
import { Factory } from "../../../proxy/Factory.sol";

/// @title BaseERC721CheckerFactory
/// @notice Factory contract for deploying minimal proxy instances of BaseERC721Checker.
/// @dev Simplifies deployment of ERC721 checker clones with appended configuration data.
contract BaseERC721CheckerFactory is Factory {
    /// @notice Initializes the factory with the BaseERC721Checker implementation.
    constructor() Factory(address(new BaseERC721Checker())) { }

    /// @notice Deploys a new BaseERC721Checker clone with the specified NFT contract address.
    /// @dev Encodes the NFT contract address as configuration data for the clone.
    /// @param _nftAddress Address of the ERC721 contract to validate ownership.
    function deploy(address _nftAddress) public {
        // Encode the NFT address for the appended data.
        bytes memory data = abi.encode(_nftAddress);

        // Deploy the clone and initialize it with the encoded data.
        address clone = super._deploy(data);

        BaseERC721Checker(clone).initialize();
    }
}
