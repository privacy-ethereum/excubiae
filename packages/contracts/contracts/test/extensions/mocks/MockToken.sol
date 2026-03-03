// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

import { ERC721 } from "@openzeppelin/contracts/token/ERC721/ERC721.sol";
import { Ownable } from "@openzeppelin/contracts/access/Ownable.sol";

/// @title MockToken
/// @notice This contract is an ERC721 token contract which
/// can be used to allow users to sign up for a poll.
contract MockToken is ERC721, Ownable(msg.sender) {
    /// @notice The constructor which calls the ERC721 constructor
    constructor() payable ERC721("MockToken", "MockToken") { }

    /// @notice Gives an ERC721 token to an address
    /// @param to The address to give the token to
    /// @param curTokenId The token id to give
    function giveToken(address to, uint256 curTokenId) public onlyOwner {
        _mint(to, curTokenId);
    }
}
