// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

/// PQ-ID registry layer (paper §III-C): DID Registry, Issuer Registry,
/// Revocation Registry, Credential Schema Registry — hosted on a single-node
/// local EVM (Anvil). A multi-node permissioned BFT deployment is future
/// work [F]. NO PII is ever stored: only DIDs, public keys, and roots.
///
/// Registry keys are bytes32 = SHA3-256(didString), computed OFF-chain
/// (FIPS-202 SHA3, not EVM keccak256) and passed in — this keeps the on-chain
/// code hash-agnostic and avoids the keccak/SHA3 padding mismatch.

contract DIDRegistry {
    struct DIDRecord {
        address controller; // tx key allowed to update (registrar of record)
        bytes publicKeyDilithium; // full ML-DSA-44 public key (1,312 bytes)
        string did; // the did:pq:... string
        string endpoints; // JSON array of service endpoints
        bool active;
        uint64 updatedAt;
    }

    mapping(bytes32 => DIDRecord) private records;

    event DIDRegistered(bytes32 indexed didKey, string did);
    event DIDDeactivated(bytes32 indexed didKey);

    function registerDID(
        bytes32 didKey,
        string calldata did,
        bytes calldata publicKeyDilithium,
        string calldata endpoints
    ) external {
        require(records[didKey].controller == address(0), "DID exists");
        records[didKey] = DIDRecord({
            controller: msg.sender,
            publicKeyDilithium: publicKeyDilithium,
            did: did,
            endpoints: endpoints,
            active: true,
            updatedAt: uint64(block.timestamp)
        });
        emit DIDRegistered(didKey, did);
    }

    function deactivateDID(bytes32 didKey) external {
        require(records[didKey].controller == msg.sender, "not controller");
        records[didKey].active = false;
        records[didKey].updatedAt = uint64(block.timestamp);
        emit DIDDeactivated(didKey);
    }

    function resolveDID(bytes32 didKey)
        external
        view
        returns (
            string memory did,
            bytes memory publicKeyDilithium,
            string memory endpoints,
            bool active
        )
    {
        DIDRecord storage r = records[didKey];
        require(r.controller != address(0), "DID not found");
        return (r.did, r.publicKeyDilithium, r.endpoints, r.active);
    }

    function controllerOf(bytes32 didKey) external view returns (address) {
        return records[didKey].controller;
    }
}

contract IssuerRegistry {
    address public immutable governance;
    mapping(bytes32 => bool) public accredited; // didKey => accredited

    event IssuerAccredited(bytes32 indexed didKey);
    event IssuerRevoked(bytes32 indexed didKey);

    constructor() {
        governance = msg.sender;
    }

    function accredit(bytes32 didKey) external {
        require(msg.sender == governance, "governance only");
        accredited[didKey] = true;
        emit IssuerAccredited(didKey);
    }

    function revokeAccreditation(bytes32 didKey) external {
        require(msg.sender == governance, "governance only");
        accredited[didKey] = false;
        emit IssuerRevoked(didKey);
    }
}

contract RevocationRegistry {
    DIDRegistry public immutable didRegistry;
    mapping(bytes32 => uint256) public revRoot; // issuer didKey => SMT root

    event RevRootUpdated(bytes32 indexed issuerDidKey, uint256 newRoot);

    constructor(DIDRegistry _didRegistry) {
        didRegistry = _didRegistry;
    }

    /// Algorithm 4: the issuer (its registered controller key) publishes a new
    /// revocation root after inserting a credID into its revoked-set SMT.
    function publishRevRoot(bytes32 issuerDidKey, uint256 newRoot) external {
        require(
            didRegistry.controllerOf(issuerDidKey) == msg.sender,
            "not issuer controller"
        );
        revRoot[issuerDidKey] = newRoot;
        emit RevRootUpdated(issuerDidKey, newRoot);
    }
}

contract SchemaRegistry {
    struct Schema {
        bytes32 schemaHash; // SHA3-256 of the canonical schema JSON
        string uri;
        bool exists;
    }

    mapping(bytes32 => Schema) public schemas; // schemaId => schema

    event SchemaRegistered(bytes32 indexed schemaId, bytes32 schemaHash, string uri);

    function registerSchema(bytes32 schemaId, bytes32 schemaHash, string calldata uri) external {
        require(!schemas[schemaId].exists, "schema exists");
        schemas[schemaId] = Schema(schemaHash, uri, true);
        emit SchemaRegistered(schemaId, schemaHash, uri);
    }
}
