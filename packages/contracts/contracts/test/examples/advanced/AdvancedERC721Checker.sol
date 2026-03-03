// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

import { AdvancedChecker } from "../../../checker/AdvancedChecker.sol";
import { BaseERC721Checker } from "../base/BaseERC721Checker.sol";
import { IERC721 } from "@openzeppelin/contracts/token/ERC721/IERC721.sol";

/// @title AdvancedERC721Checker
/// @notice Multi-phase NFT validation using external contracts and thresholds.
/// @dev Implements three-phase validation:
///      - Pre-check: Basic ownership verification using `BaseERC721Checker`.
///      - Main-check: Ensures a minimum token balance.
///      - Post-check: Validates reward eligibility.
contract AdvancedERC721Checker is AdvancedChecker {
    /// @notice External verification contracts and thresholds.
    IERC721 public signupNft;
    IERC721 public rewardNft;
    BaseERC721Checker public baseERC721Checker;

    uint256 public minBalance;
    uint256 public minTokenId;
    uint256 public maxTokenId;

    /// @notice Initializes the checker with external contract references and thresholds.
    /// @dev Decodes appended bytes to set state variables.
    function _initialize() internal override {
        super._initialize();

        bytes memory data = _getAppendedBytes();

        (
            address signupNftAddr,
            address rewardNftAddr,
            address baseCheckerAddr,
            uint256 minBalance_,
            uint256 minTokenId_,
            uint256 maxTokenId_
        ) = abi.decode(data, (address, address, address, uint256, uint256, uint256));

        signupNft = IERC721(signupNftAddr);
        rewardNft = IERC721(rewardNftAddr);
        baseERC721Checker = BaseERC721Checker(baseCheckerAddr);
        minBalance = minBalance_;
        minTokenId = minTokenId_;
        maxTokenId = maxTokenId_;
    }

    /// @notice Pre-check: Validates ownership using the base checker.
    /// @param subject Address to validate.
    /// @param evidence Encoded tokenId.
    /// @return Boolean indicating validation success.
    function _checkPre(address subject, bytes calldata evidence) internal view override returns (bool) {
        super._checkPre(subject, evidence);

        return baseERC721Checker.check(subject, evidence);
    }

    /// @notice Main-check: Ensures token balance meets requirements.
    /// @param subject Address to validate.
    /// @param evidence Not used in this validation.
    /// @return Boolean indicating validation success.
    function _checkMain(address subject, bytes calldata evidence) internal view override returns (bool) {
        super._checkMain(subject, evidence);

        return signupNft.balanceOf(subject) >= minBalance;
    }

    /// @notice Post-check: Validates reward eligibility.
    /// @param subject Address to validate.
    /// @param evidence Not used in this validation.
    /// @return Boolean indicating validation success.
    function _checkPost(address subject, bytes calldata evidence) internal view override returns (bool) {
        super._checkPost(subject, evidence);

        return rewardNft.balanceOf(subject) == 0;
    }
}
