// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

/// Circuit v3: on-chain anchor for each issuer's ML-DSA-44-signed EPOCH
/// statement (issuance-tree root + revocation root). Kept in its own file so
/// Registries.sol (and every published v2 gas and deployment figure) is
/// byte-identical.
///
/// The v3 verifier accepts a presentation only if its issRoot AND revRoot
/// equal the issuer's CURRENT anchored pair and the attached signature hashes
/// to the anchored sigHash; honest wallets refuse to present anything else.
/// So all holders of an issuer present the same two roots and signature bytes
/// during an epoch. Epochs advance by exactly one and at most once per
/// `minAnchorInterval` seconds, which caps how many distinct views an issuer
/// can hand out, and stale writes cannot roll a newer revocation root back.
/// Revocations therefore take effect at the next epoch.
///
/// Writes are authorized like RevocationRegistry.publishRevRoot: by the
/// issuer DID's registered controller (an ECDSA account, review 9.4). The
/// ML-DSA signature itself is verified off-chain against pk_issuer.
interface IDIDControllers {
    function controllerOf(bytes32 didKey) external view returns (address);
}

contract IssuanceRootRegistry {
    struct Anchor {
        uint256 root; // Poseidon issuance-tree root (BN254 field element)
        uint256 revRoot; // revocation SMT root (BN254 field element)
        uint64 epoch; // 1, 2, 3, ... per issuer
        uint64 publishedAt; // block timestamp of the anchor
        bytes32 sigHash; // SHA3-256 of the ML-DSA-44 signature over the epoch message
    }

    IDIDControllers public immutable didRegistry;
    /// Minimum seconds between two anchors of one issuer (deployment policy; wallets check it).
    uint64 public immutable minAnchorInterval;
    mapping(bytes32 => Anchor) private anchors; // issuer didKey => current anchor

    event IssuanceRootPublished(
        bytes32 indexed issuerDidKey,
        uint64 epoch,
        uint256 root,
        uint256 revRoot,
        bytes32 sigHash
    );

    constructor(IDIDControllers _didRegistry, uint64 _minAnchorInterval) {
        didRegistry = _didRegistry;
        minAnchorInterval = _minAnchorInterval;
    }

    function publishIssuanceRoot(
        bytes32 issuerDidKey,
        uint64 epoch,
        uint256 root,
        uint256 revRoot,
        bytes32 sigHash
    ) external {
        require(didRegistry.controllerOf(issuerDidKey) == msg.sender, "not issuer controller");
        Anchor storage cur = anchors[issuerDidKey];
        require(epoch == cur.epoch + 1, "epoch must be previous + 1");
        require(cur.epoch == 0 || block.timestamp >= uint256(cur.publishedAt) + minAnchorInterval, "anchor too soon");
        anchors[issuerDidKey] = Anchor(root, revRoot, epoch, uint64(block.timestamp), sigHash);
        emit IssuanceRootPublished(issuerDidKey, epoch, root, revRoot, sigHash);
    }

    function issuanceRoot(bytes32 issuerDidKey)
        external
        view
        returns (uint256 root, uint256 revRoot, uint64 epoch, bytes32 sigHash, uint64 publishedAt)
    {
        Anchor storage a = anchors[issuerDidKey];
        return (a.root, a.revRoot, a.epoch, a.sigHash, a.publishedAt);
    }
}
