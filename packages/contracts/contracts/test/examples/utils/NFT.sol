// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;

import { ERC721 } from "@openzeppelin/contracts/token/ERC721/ERC721.sol";

/// @title NFT.
/// @notice Simple ERC721 implementation for testing.
contract NFT is ERC721 {
    /// @dev Tracks the next token ID to mint.
    uint256 private _tokenIdCounter;

    /// @notice Initializes NFT with name and symbol "NFT".
    constructor() ERC721("NFT", "NFT") { }

    /// @notice Mints new token to specified address.
    /// @param to Recipient address.
    function mint(address to) external {
        _safeMint(to, _tokenIdCounter);
        _tokenIdCounter++;
    }
}
