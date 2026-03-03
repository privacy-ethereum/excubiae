// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

import { BaseChecker } from "../../../checker/BaseChecker.sol";
import { IERC721 } from "@openzeppelin/contracts/token/ERC721/IERC721.sol";

/// @title BaseERC721Checker
/// @notice ERC721 token ownership validator.
/// @dev Extends BaseChecker to implement NFT ownership validation logic.
contract BaseERC721Checker is BaseChecker {
    /// @notice Address of the ERC721 contract used for ownership validation.
    IERC721 public nft;

    /// @notice Initializes the contract with an ERC721 contract address.
    /// @dev Decodes the appended bytes from the clone to set the `nft` address.
    function _initialize() internal override {
        super._initialize();

        bytes memory data = _getAppendedBytes();

        address nftAddress = abi.decode(data, (address));

        nft = IERC721(nftAddress);
    }

    /// @notice Validates whether the subject owns a specific NFT.
    /// @dev Decodes the token ID from evidence and checks ownership via the ERC721 contract.
    /// @param subject Address to validate ownership for.
    /// @param evidence Encoded token ID used for validation.
    /// @return Boolean indicating whether the subject owns the token.
    function _check(address subject, bytes calldata evidence) internal view override returns (bool) {
        super._check(subject, evidence);

        uint256 tokenId = abi.decode(evidence, (uint256));

        return nft.ownerOf(tokenId) == subject;
    }
}
