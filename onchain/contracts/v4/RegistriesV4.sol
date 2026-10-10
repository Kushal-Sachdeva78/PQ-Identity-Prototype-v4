// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

// PQ-Identity v4 registries (docs/v4/V4_DESIGN.md section 4): DID records with an
// ML-DSA-44 proof of possession, governance accreditation statements, issuer epoch
// anchors, and verifier ML-KEM-768 keys.
//
// Trust model (repeated in each contract's NatSpec):
// - EVM authorization (every msg.sender check below) is liveness only. It decides which
//   account may post data and pay gas. It never decides whether a wallet or verifier
//   accepts anything.
// - Trust comes from ML-DSA-44 signed statements (V4_DESIGN section 3) that wallets and
//   verifiers check off chain: the DID's own key for proof of possession, the pinned
//   governance key for accreditation, the issuer key for epochs, the verifier key for
//   KEM keys. These contracts never verify ML-DSA signatures and never parse statements.
// - Storage keeps keccak256 hashes of large signed objects. Events carry the full bytes;
//   clients read them from the logs and check them against the stored hashes.
// - Revert reasons start with the registry check name of V4_DESIGN 6.3 (recordUnique,
//   controllerOnly, epochIncrement, anchorCadence, windowBounds, governanceWriter,
//   accreditationSerial, kemMonotonic).
// - The v2/v3 contracts (Registries.sol, IssuanceRootRegistry.sol) are separate and unchanged.

/// @notice Record key shared by all v4 registries.
library RecordKeyV4 {
    /// @notice recordKey = keccak256(abi.encodePacked(did, controller)).
    /// @dev Indexing only. The packed encoding is unambiguous because the controller is
    /// always the last 20 bytes. One DID string may have many records (one per controller);
    /// which record is authoritative is decided by the governance-signed accreditation that
    /// verifiers check off chain, not by this contract.
    function compute(string calldata did, address controller) internal pure returns (bytes32) {
        return keccak256(abi.encodePacked(did, controller));
    }
}

/// @notice Read interface used by the epoch and KEM registries.
interface IDIDRegistryV4 {
    function isActive(bytes32 recordKey) external view returns (bool);
}

/// @title DIDRegistryV4
/// @notice DID records keyed by (did, controller). Registration is first-come per
/// (did, controller) pair only, so a squatter cannot block another controller. Each record
/// carries an ML-DSA-44 proof-of-possession signature over
/// {type:"pqid:did-pop:v1", did, controller, chainId, registry, nonce, origin}; the contract
/// stores its hash and emits the full bytes. Verifiers and wallets check the signature off
/// chain, rebuilding the statement with the stored origin, so an origin chosen by the
/// submitting EVM account and not signed by the DID key fails the check.
/// @dev EVM authorization is liveness only: msg.sender decides which record a call writes,
/// never whether a record is trusted. Trust in a record comes from its ML-DSA-44 proof of
/// possession and the governance-signed accreditation, both verified off chain. A DID string
/// may have many records; the chain does not pick the authoritative one.
contract DIDRegistryV4 is IDIDRegistryV4 {
    struct Record {
        bytes pk; // raw ML-DSA-44 public key (1312 bytes for honest callers; not checked here)
        bytes32 popNonce; // nonce inside the signed proof-of-possession statement
        bytes32 popSigHash; // keccak256 of the PoP signature (full bytes in DIDRegisteredV4)
        string origin; // registered web origin (wallet origin-binding mode); signed inside the PoP
        bool exists;
        bool active;
        uint64 registeredAt; // block timestamp of registration
        uint64 registeredBlock; // block number of registration (locates the event log)
    }

    mapping(bytes32 => Record) private records;

    event DIDRegisteredV4(
        bytes32 indexed recordKey,
        string did,
        address indexed controller,
        bytes32 popNonce,
        bytes popSig
    );
    event DIDDeactivatedV4(bytes32 indexed recordKey, string did, address indexed controller);

    /// @notice Register (did, msg.sender). Check recordUnique: reverts if that record exists.
    /// @dev msg.sender becomes the controller. Liveness only: the proof of possession inside
    /// popSig, not this call, is what binds the DID key to the controller.
    function registerDID(
        string calldata did,
        bytes calldata pk,
        bytes32 popNonce,
        bytes calldata popSig,
        string calldata origin
    ) external {
        bytes32 key = RecordKeyV4.compute(did, msg.sender);
        Record storage r = records[key];
        require(!r.exists, "recordUnique: record exists for (did, controller)");
        r.pk = pk;
        r.popNonce = popNonce;
        r.popSigHash = keccak256(popSig);
        r.origin = origin;
        r.exists = true;
        r.active = true;
        r.registeredAt = uint64(block.timestamp);
        r.registeredBlock = uint64(block.number);
        emit DIDRegisteredV4(key, did, msg.sender, popNonce, popSig);
    }

    /// @notice Deactivate (did, msg.sender). Check controllerOnly: only that record's
    /// controller can deactivate it, and only while it is active.
    function deactivate(string calldata did) external {
        bytes32 key = RecordKeyV4.compute(did, msg.sender);
        Record storage r = records[key];
        require(r.active, "controllerOnly: no active record for (did, sender)");
        r.active = false;
        emit DIDDeactivatedV4(key, did, msg.sender);
    }

    /// @notice The record of (did, controller); exists == false if there is none.
    function resolve(string calldata did, address controller) external view returns (Record memory) {
        return records[RecordKeyV4.compute(did, controller)];
    }

    /// @notice The record under a precomputed record key.
    function resolveByKey(bytes32 recordKey) external view returns (Record memory) {
        return records[recordKey];
    }

    function isActive(bytes32 recordKey) external view override returns (bool) {
        return records[recordKey].active;
    }

    /// @notice recordKey(did, controller), for off-chain cross-checks.
    function recordKeyOf(string calldata did, address controller) external pure returns (bytes32) {
        return RecordKeyV4.compute(did, controller);
    }
}

/// @title AccreditationRegistryV4
/// @notice Publishes governance-signed accreditation statements
/// {type:"pqid:accreditation:v2", issuerDid, controller, pkSha3, chainId, registry, serial,
/// status, notBefore, notAfter}. Check governanceWriter: only the governance EVM account may
/// publish. Check accreditationSerial: the declared signed serial strictly increases per
/// issuer DID, by at most 2^20 per publication, and never exceeds 2^53 - 1.
/// @dev The governance EVM account is a constructor argument (a dedicated key), not the
/// deployer. Its authority is liveness only: a verifier accepts an accreditation only if the
/// statement verifies under the pinned governance ML-DSA-44 key, names this chain and this
/// registry, is in its window, binds the issuer's did, controller and key hash, and carries
/// exactly the serial this registry recorded. A compromised governance EVM key can withhold
/// statements (bounded by the statement window) or re-post one of this registry's own
/// statements with a higher declared serial (which verifiers and wallets then reject because
/// the statement's serial differs from the recorded one); it cannot forge one or move one from
/// another deployment.
contract AccreditationRegistryV4 {
    struct Latest {
        bytes32 statementHash; // keccak256 of the canonical JSON statement bytes
        bytes32 signatureHash; // keccak256 of the ML-DSA-44 signature
        uint64 serial; // on-chain publication counter for this issuer DID (1, 2, ...);
        // the trusted serial is the one inside the signed statement
        uint64 publishedAt; // block timestamp
        uint64 publishedBlock; // block number (locates the event log)
        uint64 signedSerial; // serial field inside the signed statement; must strictly increase
    }

    /// @notice Largest signed serial: statements carry the serial as a JSON number, which must
    /// be a safe integer (2^53 - 1), so no valid statement can carry a larger one.
    uint64 public constant MAX_SIGNED_SERIAL = 2 ** 53 - 1;
    /// @notice Largest step of the signed serial per publication. Without it, one publication
    /// with a huge serial (a misused or buggy governance EVM transaction) would block every
    /// later genuine statement for that DID for good, since `governance` is immutable.
    uint64 public constant MAX_SERIAL_STEP = 2 ** 20;

    address public immutable governance;
    mapping(bytes32 => Latest) private latestOf; // keccak256(bytes(issuerDid)) => latest

    event AccreditationPublishedV4(
        bytes32 indexed issuerKey,
        string issuerDid,
        uint64 serial,
        uint64 signedSerial,
        bytes statement,
        bytes signature
    );

    constructor(address governance_) {
        require(governance_ != address(0), "governance account is zero");
        governance = governance_;
    }

    /// @notice Publish the latest accreditation statement for issuerDid (governance account only).
    /// @dev Check accreditationSerial: `signedSerial` must exceed the previous one, by at most
    /// MAX_SERIAL_STEP, and must not exceed MAX_SIGNED_SERIAL. Verifiers require it to equal
    /// the serial inside the ML-DSA-signed statement, so an older genuine statement (lower
    /// serial) can never be re-posted as the latest (route RA-c), and the caps keep one bad
    /// publication from blocking the DID for good (governance derives its next serial from
    /// the stored one, so it can always post a larger valid serial).
    function publish(
        string calldata issuerDid,
        uint64 signedSerial,
        bytes calldata statement,
        bytes calldata signature
    ) external {
        require(msg.sender == governance, "governanceWriter: sender is not the governance account");
        bytes32 k = keccak256(bytes(issuerDid));
        Latest storage l = latestOf[k];
        require(signedSerial > l.signedSerial, "accreditationSerial: signed serial must increase");
        require(signedSerial <= MAX_SIGNED_SERIAL, "accreditationSerial: signed serial above 2^53 - 1");
        require(
            uint256(signedSerial) <= uint256(l.signedSerial) + MAX_SERIAL_STEP,
            "accreditationSerial: signed serial step above 2^20"
        );
        l.signedSerial = signedSerial;
        uint64 serial = l.serial + 1;
        l.statementHash = keccak256(statement);
        l.signatureHash = keccak256(signature);
        l.serial = serial;
        l.publishedAt = uint64(block.timestamp);
        l.publishedBlock = uint64(block.number);
        emit AccreditationPublishedV4(k, issuerDid, serial, signedSerial, statement, signature);
    }

    /// @notice Latest publication for issuerDid; serial == 0 if there is none.
    function latest(string calldata issuerDid) external view returns (Latest memory) {
        return latestOf[keccak256(bytes(issuerDid))];
    }

    function issuerKeyOf(string calldata issuerDid) external pure returns (bytes32) {
        return keccak256(bytes(issuerDid));
    }
}

/// @title IssuanceRootRegistryV4
/// @notice Anchors each issuer record's current epoch: issuance root, revocation root,
/// validity window and the hash of the issuer's ML-DSA-44 signature over
/// {type:"pqid:issuer-epoch:v4", ...}. Checks: controllerOnly (the record (did, msg.sender)
/// exists and is active), epochIncrement (epoch == current + 1), anchorCadence (at least
/// minAnchorInterval seconds after the previous anchor), windowBounds
/// (notBefore < notAfter <= notBefore + maxWindow).
/// @dev EVM authorization is liveness only: the controller check decides who may post an
/// anchor, while acceptance rests on the issuer's ML-DSA-44 epoch signature verified off
/// chain. The cadence and window rules cap how many distinct views one issuer can hand out and
/// how long a frozen anchor stays usable. They are liveness and hygiene rules: verifiers
/// still check the epoch statement's ML-DSA-44 signature, its window and that its sigHash
/// equals the anchored one. Honest wallets refuse registries whose minAnchorInterval is
/// below their floor.
contract IssuanceRootRegistryV4 {
    struct Anchor {
        uint256 root; // Poseidon issuance-tree root (BN254 field element)
        uint256 revRoot; // revocation IMT root (BN254 field element)
        bytes32 sigHash; // hash of the ML-DSA-44 signature over the epoch statement
        uint64 epoch; // 1, 2, 3, ... per record
        uint64 notBefore; // unix seconds
        uint64 notAfter; // unix seconds
        uint64 publishedAt; // block timestamp of the anchor
        uint64 publishedBlock; // block number of the anchor
    }

    IDIDRegistryV4 public immutable didRegistry;
    /// @notice Minimum seconds between two anchors of one record (deployment policy).
    uint64 public immutable minAnchorInterval;
    /// @notice Maximum epoch window length notAfter - notBefore (seconds).
    uint64 public immutable maxWindow;
    mapping(bytes32 => Anchor) private anchors; // recordKey => current anchor

    event EpochPublishedV4(
        bytes32 indexed recordKey,
        address indexed controller,
        uint64 epoch,
        uint256 root,
        uint256 revRoot,
        uint64 notBefore,
        uint64 notAfter,
        bytes32 sigHash
    );

    constructor(IDIDRegistryV4 didRegistry_, uint64 minAnchorInterval_, uint64 maxWindow_) {
        require(maxWindow_ > 0, "maxWindow is zero");
        didRegistry = didRegistry_;
        minAnchorInterval = minAnchorInterval_;
        maxWindow = maxWindow_;
    }

    function publishEpoch(
        string calldata did,
        uint64 epoch,
        uint256 root,
        uint256 revRoot,
        uint64 notBefore,
        uint64 notAfter,
        bytes32 sigHash
    ) external {
        bytes32 key = RecordKeyV4.compute(did, msg.sender);
        require(didRegistry.isActive(key), "controllerOnly: no active DID record for (did, sender)");
        Anchor storage cur = anchors[key];
        require(epoch == uint256(cur.epoch) + 1, "epochIncrement: epoch must be current + 1");
        require(
            cur.epoch == 0 || block.timestamp >= uint256(cur.publishedAt) + minAnchorInterval,
            "anchorCadence: anchor too soon"
        );
        require(
            notBefore < notAfter && uint256(notAfter) <= uint256(notBefore) + maxWindow,
            "windowBounds: need notBefore < notAfter <= notBefore + maxWindow"
        );
        cur.root = root;
        cur.revRoot = revRoot;
        cur.sigHash = sigHash;
        cur.epoch = epoch;
        cur.notBefore = notBefore;
        cur.notAfter = notAfter;
        cur.publishedAt = uint64(block.timestamp);
        cur.publishedBlock = uint64(block.number);
        emit EpochPublishedV4(key, msg.sender, epoch, root, revRoot, notBefore, notAfter, sigHash);
    }

    /// @notice Current anchor of (did, controller); epoch == 0 if none was published.
    function current(string calldata did, address controller) external view returns (Anchor memory) {
        return anchors[RecordKeyV4.compute(did, controller)];
    }
}

/// @title VerifierKemRegistryV4
/// @notice A verifier record's current ML-KEM-768 public key, with the verifier's ML-DSA-44
/// signed statement {type:"pqid:verifier-kem:v1", ..., kemPkSha3, notBefore, notAfter}.
/// Checks: controllerOnly (the record (did, msg.sender) must exist and be active);
/// kemMonotonic (the declared statement notBefore strictly increases per record, so an older
/// genuine statement cannot be re-posted to undo a key rotation).
/// @dev EVM authorization is liveness only: the controller check decides who may post a key,
/// while acceptance rests on the verifier's ML-DSA-44 statement verified off chain.
/// Stores hashes; the event carries the full key, statement and signature. Wallets take
/// the KEM key from here (never from a request) and accept it only if the statement verifies
/// under the verifier record's ML-DSA key, matches the key's SHA3-256, names this chain and
/// this registry, and carries the notBefore this registry recorded (as for the accreditation
/// serial, the contract never parses the statement: the caller declares notBefore and
/// readers compare it with the signed value).
contract VerifierKemRegistryV4 {
    struct KemKey {
        bytes32 kemPkHash; // keccak256 of the raw ML-KEM-768 public key
        bytes32 statementHash; // keccak256 of the canonical JSON statement bytes
        bytes32 signatureHash; // keccak256 of the ML-DSA-44 signature
        uint64 version; // 1, 2, ... per record
        uint64 publishedAt; // block timestamp
        uint64 publishedBlock; // block number (locates the event log)
        uint64 notBefore; // notBefore inside the signed statement; must strictly increase
    }

    /// @notice Largest notBefore: statements carry it as a JSON number, which must be a safe
    /// integer (2^53 - 1), so no valid statement can carry a larger one.
    uint64 public constant MAX_NOT_BEFORE = 2 ** 53 - 1;

    IDIDRegistryV4 public immutable didRegistry;
    mapping(bytes32 => KemKey) private keys; // recordKey => current KEM key

    event KemKeyPublishedV4(
        bytes32 indexed recordKey,
        address indexed controller,
        uint64 version,
        uint64 notBefore,
        bytes kemPk,
        bytes statement,
        bytes signature
    );

    constructor(IDIDRegistryV4 didRegistry_) {
        didRegistry = didRegistry_;
    }

    /// @notice Publish the KEM key of (did, msg.sender). `notBefore` is the statement's signed
    /// notBefore (readers refuse a statement whose notBefore differs from the stored one).
    /// @dev Check kemMonotonic: notBefore must exceed the record's previous one and must not
    /// exceed MAX_NOT_BEFORE. Only the record's controller can post here, and it can already
    /// deactivate the record, so the value is not capped against the block time.
    function publishKemKey(
        string calldata did,
        uint64 notBefore,
        bytes calldata kemPk,
        bytes calldata statement,
        bytes calldata signature
    ) external {
        bytes32 key = RecordKeyV4.compute(did, msg.sender);
        require(didRegistry.isActive(key), "controllerOnly: no active DID record for (did, sender)");
        KemKey storage k = keys[key];
        require(notBefore > k.notBefore, "kemMonotonic: statement notBefore must increase");
        require(notBefore <= MAX_NOT_BEFORE, "kemMonotonic: statement notBefore above 2^53 - 1");
        uint64 version = k.version + 1;
        k.kemPkHash = keccak256(kemPk);
        k.statementHash = keccak256(statement);
        k.signatureHash = keccak256(signature);
        k.version = version;
        k.publishedAt = uint64(block.timestamp);
        k.publishedBlock = uint64(block.number);
        k.notBefore = notBefore;
        emit KemKeyPublishedV4(key, msg.sender, version, notBefore, kemPk, statement, signature);
    }

    /// @notice Current KEM key of (did, controller); version == 0 if none was published.
    function latest(string calldata did, address controller) external view returns (KemKey memory) {
        return keys[RecordKeyV4.compute(did, controller)];
    }
}
