// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

import { AdvancedERC721Checker } from "./AdvancedERC721Checker.sol";
import { Factory } from "../../../proxy/Factory.sol";

/// @title AdvancedERC721CheckerFactory
/// @notice Factory for deploying minimal proxy instances of AdvancedERC721Checker.
/// @dev Encodes configuration data for each clone.
contract AdvancedERC721CheckerFactory is Factory {
    /// @notice Initializes the factory with the AdvancedERC721Checker implementation.
    constructor() Factory(address(new AdvancedERC721Checker())) { }

    /// @notice Deploys a new AdvancedERC721Checker clone.
    /// @dev Encodes and appends configuration data for the clone.
    /// @param _nftAddress Address of the signup NFT contract.
    /// @param _rewardNft Address of the reward NFT contract.
    /// @param _baseERC721Checker Address of the base checker contract.
    /// @param _minBalance Minimum balance required for validation.
    /// @param _minTokenId Minimum token ID for validation.
    /// @param _maxTokenId Maximum token ID for validation.
    function deploy(
        address _nftAddress,
        address _rewardNft,
        address _baseERC721Checker,
        uint256 _minBalance,
        uint256 _minTokenId,
        uint256 _maxTokenId
    )
        public
    {
        bytes memory data =
            abi.encode(_nftAddress, _rewardNft, _baseERC721Checker, _minBalance, _minTokenId, _maxTokenId);

        address clone = super._deploy(data);

        AdvancedERC721Checker(clone).initialize();
    }
}
