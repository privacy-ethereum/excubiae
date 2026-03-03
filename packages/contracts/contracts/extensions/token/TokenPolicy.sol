// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

import { ERC721 } from "@openzeppelin/contracts/token/ERC721/ERC721.sol";

import { BasePolicy } from "../../policy/BasePolicy.sol";

/// @title TokenPolicy
/// @notice This contract allows to enforce users by token ownership
/// by requiring new voters to own a certain ERC721 token
contract TokenPolicy is BasePolicy {
    /// @notice a mapping of tokenIds to whether they have been used to enforce
    mapping(uint256 => bool) public enforcedTokenIds;

    /// @notice creates a new TokenPolicy
    // solhint-disable-next-line no-empty-blocks
    constructor() payable { }

    /// @notice Enforces the user if they own the token with the token ID encoded in
    /// _data. Throws if the user does not own the token or if the token has
    /// already been used to sign up.
    /// @param _subject The user's Ethereum address.
    /// @param _evidence The ABI-encoded tokenId as a uint256.
    function _enforce(address _subject, bytes calldata _evidence) internal override {
        // Decode the given _data bytes into a uint256 which is the token ID
        uint256 tokenId = abi.decode(_evidence, (uint256));

        // Check if the token has already been used
        if (enforcedTokenIds[tokenId]) {
            revert AlreadyEnforced();
        }

        // Mark the token as already used
        enforcedTokenIds[tokenId] = true;

        super._enforce(_subject, _evidence);
    }

    /// @notice Get the trait of the Policy
    /// @return The type of the Policy
    function trait() public pure override returns (string memory) {
        return "Token";
    }
}
