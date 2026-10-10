// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

// Fuzz and invariant tests of onchain/contracts/v4/RegistriesV4.sol (robustness row,
// DECISIONS D-034; docs/v4/ROBUSTNESS.md section 6). The contracts are imported unchanged.
//
// Method: every call is checked against an independent model of the four registries written
// from the contract NatSpec and V4_DESIGN 6.3 (registry check names): the model predicts
// whether a call is accepted and, if not, the exact revert reason of the first failing check;
// after every call the stored state must equal the model's. Stateless fuzz tests cover single
// calls and short sequences; the invariant test lets forge drive random call sequences through
// a handler that keeps the model (ghost state) and counts disagreements.
//
// Seed 20261024 (robustness.forgeFuzz) and budgets come from the driver
// (harness/v4/robustness/forge_fuzz.ts). forge-std is not vendored (no downloads): the few
// cheatcodes used are declared below.

import {
    DIDRegistryV4,
    AccreditationRegistryV4,
    IssuanceRootRegistryV4,
    VerifierKemRegistryV4,
    IDIDRegistryV4
} from "../../contracts/v4/RegistriesV4.sol";

interface Vm {
    function prank(address sender) external;
    function warp(uint256 timestamp) external;
    function roll(uint256 blockNumber) external;
    function assume(bool condition) external pure;
}

abstract contract RegistryModelBase {
    Vm internal constant vm = Vm(address(uint160(uint256(keccak256("hevm cheat code")))));

    uint64 internal constant MIN_INTERVAL = 3600; // MIN_ANCHOR_INTERVAL_SEC (packages/v4/src/constants.ts)
    uint64 internal constant MAX_WINDOW = 86400; // MAX_EPOCH_WINDOW_SEC
    uint64 internal constant MAX_SAFE = 2 ** 53 - 1; // MAX_SIGNED_SERIAL and MAX_NOT_BEFORE
    uint64 internal constant MAX_STEP = 2 ** 20; // MAX_SERIAL_STEP

    string internal constant R_RECORD_UNIQUE = "recordUnique: record exists for (did, controller)";
    string internal constant R_DEACTIVATE = "controllerOnly: no active record for (did, sender)";
    string internal constant R_CONTROLLER = "controllerOnly: no active DID record for (did, sender)";
    string internal constant R_GOVERNANCE = "governanceWriter: sender is not the governance account";
    string internal constant R_SERIAL_INCREASE = "accreditationSerial: signed serial must increase";
    string internal constant R_SERIAL_MAX = "accreditationSerial: signed serial above 2^53 - 1";
    string internal constant R_SERIAL_STEP = "accreditationSerial: signed serial step above 2^20";
    string internal constant R_EPOCH_INCREMENT = "epochIncrement: epoch must be current + 1";
    string internal constant R_CADENCE = "anchorCadence: anchor too soon";
    string internal constant R_WINDOW = "windowBounds: need notBefore < notAfter <= notBefore + maxWindow";
    string internal constant R_KEM_INCREASE = "kemMonotonic: statement notBefore must increase";
    string internal constant R_KEM_MAX = "kemMonotonic: statement notBefore above 2^53 - 1";

    function same(string memory a, string memory b) internal pure returns (bool) {
        return keccak256(bytes(a)) == keccak256(bytes(b));
    }

    function startsWith(string memory s, string memory prefix) internal pure returns (bool) {
        bytes memory a = bytes(s);
        bytes memory p = bytes(prefix);
        if (a.length < p.length) return false;
        for (uint256 i = 0; i < p.length; i++) if (a[i] != p[i]) return false;
        return true;
    }

    function keyOf(string memory did, address controller) internal pure returns (bytes32) {
        return keccak256(abi.encodePacked(did, controller));
    }

    // ---------------------------------------------------------------- the model's decisions

    function expectSerial(address sender, address governance, uint64 last, uint64 s) internal pure returns (string memory) {
        if (sender != governance) return R_GOVERNANCE;
        if (s <= last) return R_SERIAL_INCREASE;
        if (s > MAX_SAFE) return R_SERIAL_MAX;
        if (uint256(s) > uint256(last) + MAX_STEP) return R_SERIAL_STEP;
        return "";
    }

    function expectEpoch(
        bool active,
        uint64 curEpoch,
        uint64 lastPublishedAt,
        uint64 epoch,
        uint64 nb,
        uint64 na,
        uint256 nowTs
    ) internal pure returns (string memory) {
        if (!active) return R_CONTROLLER;
        if (uint256(epoch) != uint256(curEpoch) + 1) return R_EPOCH_INCREMENT;
        if (curEpoch != 0 && nowTs < uint256(lastPublishedAt) + MIN_INTERVAL) return R_CADENCE;
        if (!(nb < na && uint256(na) <= uint256(nb) + MAX_WINDOW)) return R_WINDOW;
        return "";
    }

    function expectKem(bool active, uint64 lastNb, uint64 nb) internal pure returns (string memory) {
        if (!active) return R_CONTROLLER;
        if (nb <= lastNb) return R_KEM_INCREASE;
        if (nb > MAX_SAFE) return R_KEM_MAX;
        return "";
    }

    // ---------------------------------------------------------------- value pickers (edges first)

    /// A signed serial near the rule edges relative to `last`, or the raw value.
    function pickSerial(uint256 raw, uint64 last) internal pure returns (uint64) {
        uint256 m = raw % 10;
        uint256 r = raw >> 8;
        if (m == 0) return last == type(uint64).max ? last : last + 1;
        if (m == 1) return last;
        if (m == 2) return uint64((uint256(last) + MAX_STEP) % (uint256(type(uint64).max) + 1));
        if (m == 3) return uint64((uint256(last) + MAX_STEP + 1) % (uint256(type(uint64).max) + 1));
        if (m == 4) return MAX_SAFE;
        if (m == 5) return MAX_SAFE + 1;
        if (m == 6) return 0;
        if (m == 7) return uint64(uint256(last) + 1 + (r % MAX_STEP) > type(uint64).max ? last : uint256(last) + 1 + (r % MAX_STEP));
        if (m == 8) return type(uint64).max;
        return uint64(r);
    }

    /// An epoch near the rule edges relative to `cur`, or the raw value.
    function pickEpoch(uint256 raw, uint64 cur) internal pure returns (uint64) {
        uint256 m = raw % 6;
        if (m <= 2) return cur == type(uint64).max ? cur : cur + 1;
        if (m == 3) return cur;
        if (m == 4) return cur < type(uint64).max - 1 ? cur + 2 : cur;
        return uint64(raw >> 8);
    }

    /// A (notBefore, notAfter) window near the rule edges, or raw values.
    function pickWindow(uint256 raw, uint256 nowTs) internal pure returns (uint64 nb, uint64 na) {
        uint256 m = raw % 9;
        uint256 r = raw >> 8;
        nb = uint64(nowTs % (uint256(type(uint64).max) - 2 * MAX_WINDOW));
        if (m == 0) return (nb, nb + MAX_WINDOW); // longest valid window
        if (m == 1) return (nb, nb + 1 + uint64(r % MAX_WINDOW)); // a valid window
        if (m == 2) return (nb, nb); // empty window
        if (m == 3) return (nb + 1, nb); // inverted
        if (m == 4) return (nb, nb + MAX_WINDOW + 1); // one second too long
        if (m == 5) return (type(uint64).max - 1, type(uint64).max); // at the top of uint64
        if (m == 6) return (type(uint64).max - MAX_WINDOW, type(uint64).max); // longest window at the top
        if (m == 7) return (0, MAX_WINDOW);
        return (uint64(r), uint64(r >> 64));
    }

    /// A KEM statement notBefore near the rule edges relative to `last`, or the raw value.
    function pickNotBefore(uint256 raw, uint64 last) internal pure returns (uint64) {
        uint256 m = raw % 7;
        uint256 r = raw >> 8;
        if (m <= 1) return last == type(uint64).max ? last : last + 1 + uint64(r % 1_000_000);
        if (m == 2) return last;
        if (m == 3) return last == 0 ? 0 : last - 1;
        if (m == 4) return MAX_SAFE;
        if (m == 5) return MAX_SAFE + 1;
        return uint64(r);
    }
}

/// Stateless fuzz tests: single calls and short sequences, each against the model.
contract RegistriesV4FuzzTest is RegistryModelBase {
    address internal constant GOV = address(0x60F);

    DIDRegistryV4 internal dids;
    AccreditationRegistryV4 internal acc;
    IssuanceRootRegistryV4 internal roots;
    VerifierKemRegistryV4 internal kems;

    function setUp() public {
        dids = new DIDRegistryV4();
        acc = new AccreditationRegistryV4(GOV);
        roots = new IssuanceRootRegistryV4(IDIDRegistryV4(address(dids)), MIN_INTERVAL, MAX_WINDOW);
        kems = new VerifierKemRegistryV4(IDIDRegistryV4(address(dids)));
    }

    function usable(address a) internal view returns (bool) {
        return a != address(vm) && a != address(this) && a != address(dids) && a != address(acc) && a != address(roots) && a != address(kems);
    }

    /// The constructors refuse a zero governance account and a zero maxWindow.
    function test_constructorGuards() public {
        try new AccreditationRegistryV4(address(0)) {
            revert("accepted a zero governance account");
        } catch Error(string memory reason) {
            require(same(reason, "governance account is zero"), reason);
        }
        try new IssuanceRootRegistryV4(IDIDRegistryV4(address(dids)), MIN_INTERVAL, 0) {
            revert("accepted maxWindow 0");
        } catch Error(string memory reason) {
            require(same(reason, "maxWindow is zero"), reason);
        }
    }

    /// recordKeyOf is keccak256(abi.encodePacked(did, controller)) for every input.
    function testFuzz_recordKeyIsPackedHash(string memory did, address controller) public view {
        require(dids.recordKeyOf(did, controller) == keyOf(did, controller), "recordKeyOf differs from keccak256(abi.encodePacked(did, controller))");
    }

    /// Distinct (did, controller) pairs have distinct record keys (the controller is always the last 20 bytes).
    function testFuzz_recordKeyInjective(string memory d1, address c1, string memory d2, address c2) public view {
        bool samePair = same(d1, d2) && c1 == c2;
        require((dids.recordKeyOf(d1, c1) == dids.recordKeyOf(d2, c2)) == samePair, "record keys collide for distinct pairs");
    }

    /// Registration stores exactly what was sent; the pair cannot register twice; another controller still can.
    function testFuzz_registerResolveUnique(
        string memory did,
        bytes memory pk,
        bytes32 nonce,
        bytes memory sig,
        string memory origin,
        address a,
        address b,
        uint32 dt
    ) public {
        vm.assume(a != b && usable(a) && usable(b));
        vm.warp(block.timestamp + dt);
        vm.prank(a);
        dids.registerDID(did, pk, nonce, sig, origin);
        DIDRegistryV4.Record memory r = dids.resolve(did, a);
        require(r.exists && r.active, "record not active after registration");
        require(keccak256(r.pk) == keccak256(pk), "pk not stored as sent");
        require(r.popNonce == nonce && r.popSigHash == keccak256(sig), "PoP nonce or signature hash not stored as sent");
        require(same(r.origin, origin), "origin not stored as sent");
        require(r.registeredAt == uint64(block.timestamp) && r.registeredBlock == uint64(block.number), "registration time or block wrong");
        require(dids.isActive(keyOf(did, a)), "isActive false after registration");
        require(dids.resolveByKey(keyOf(did, a)).exists, "resolveByKey misses the record");
        require(!dids.resolve(did, b).exists, "registration visible under another controller");
        vm.prank(a);
        try dids.registerDID(did, pk, nonce, sig, origin) {
            revert("second registration of the same (did, controller) accepted");
        } catch Error(string memory reason) {
            require(same(reason, R_RECORD_UNIQUE), reason);
        }
        vm.prank(b);
        dids.registerDID(did, pk, nonce, sig, origin);
        require(dids.resolve(did, b).active, "a first registration blocked another controller");
    }

    /// Only the record's controller deactivates it, once; a deactivated pair can never register again.
    function testFuzz_deactivateOnlyOwn(string memory did, address a, address b) public {
        vm.assume(a != b && usable(a) && usable(b));
        vm.prank(a);
        dids.registerDID(did, hex"01", bytes32(0), hex"02", "");
        vm.prank(b);
        try dids.deactivate(did) {
            revert("another controller deactivated the record");
        } catch Error(string memory reason) {
            require(same(reason, R_DEACTIVATE), reason);
        }
        require(dids.resolve(did, a).active, "foreign deactivate changed the record");
        vm.prank(a);
        dids.deactivate(did);
        DIDRegistryV4.Record memory r = dids.resolve(did, a);
        require(r.exists && !r.active && !dids.isActive(keyOf(did, a)), "deactivate did not deactivate");
        vm.prank(a);
        try dids.deactivate(did) {
            revert("deactivated twice");
        } catch Error(string memory reason) {
            require(same(reason, R_DEACTIVATE), reason);
        }
        vm.prank(a);
        try dids.registerDID(did, hex"01", bytes32(0), hex"02", "") {
            revert("re-registration after deactivation accepted");
        } catch Error(string memory reason) {
            require(same(reason, R_RECORD_UNIQUE), reason);
        }
    }

    function accCall(address sender, string memory did, uint64 s, uint64 last, bytes memory st, bytes memory sig) internal returns (bool) {
        string memory want = expectSerial(sender, GOV, last, s);
        vm.prank(sender);
        try acc.publish(did, s, st, sig) {
            require(bytes(want).length == 0, string.concat("accepted; the model expected: ", want));
            return true;
        } catch Error(string memory reason) {
            require(bytes(want).length > 0, string.concat("rejected an allowed publication: ", reason));
            require(same(reason, want), string.concat("revert reason '", reason, "' differs from the model's '", want, "'"));
            return false;
        }
    }

    /// Accreditation publications follow governanceWriter and accreditationSerial exactly, over three calls.
    function testFuzz_accreditationSerial(string memory did, uint256 r1, uint256 r2, uint256 r3, address stranger, bytes memory st, bytes memory sig) public {
        vm.assume(usable(stranger));
        uint64 last = 0;
        uint64 count = 0;
        uint256[3] memory raws = [r1, r2, r3];
        for (uint256 i = 0; i < 3; i++) {
            address sender = (raws[i] >> 200) % 5 == 0 ? stranger : GOV;
            uint64 s = pickSerial(raws[i], last);
            vm.roll(block.number + 1);
            vm.warp(block.timestamp + 7);
            if (accCall(sender, did, s, last, st, sig)) {
                last = s;
                count++;
                AccreditationRegistryV4.Latest memory l = acc.latest(did);
                require(l.statementHash == keccak256(st) && l.signatureHash == keccak256(sig), "hashes not stored");
                require(l.publishedAt == uint64(block.timestamp) && l.publishedBlock == uint64(block.number), "publication time or block wrong");
            }
            AccreditationRegistryV4.Latest memory cur = acc.latest(did);
            require(cur.serial == count && cur.signedSerial == last, "stored serials differ from the model");
            require(cur.signedSerial <= MAX_SAFE, "signed serial above 2^53 - 1 stored");
        }
    }

    /// Register (did, ctl) or not: regState mod 3 = 0 no record, 1 active, 2 deactivated. Returns whether it is active.
    function setupRecord(string memory did, address ctl, uint8 regState) internal returns (bool) {
        if (regState % 3 == 0) return false;
        vm.prank(ctl);
        dids.registerDID(did, hex"01", bytes32(0), hex"02", "");
        if (regState % 3 == 1) return true;
        vm.prank(ctl);
        dids.deactivate(did);
        return false;
    }

    /// One publishEpoch attempt against the model; returns the model's anchor afterwards.
    function epochStep(string memory did, address ctl, bool active, uint256 raw, IssuanceRootRegistryV4.Anchor memory cur)
        internal
        returns (IssuanceRootRegistryV4.Anchor memory next)
    {
        next = cur;
        IssuanceRootRegistryV4.Anchor memory a;
        a.epoch = pickEpoch(raw, cur.epoch);
        (a.notBefore, a.notAfter) = pickWindow(raw >> 16, block.timestamp);
        a.root = raw >> 128;
        a.revRoot = raw & type(uint128).max;
        a.sigHash = keccak256(abi.encode(raw));
        a.publishedAt = uint64(block.timestamp);
        a.publishedBlock = uint64(block.number);
        string memory want = expectEpoch(active, cur.epoch, cur.publishedAt, a.epoch, a.notBefore, a.notAfter, block.timestamp);
        vm.prank(ctl);
        try roots.publishEpoch(did, a.epoch, a.root, a.revRoot, a.notBefore, a.notAfter, a.sigHash) {
            require(bytes(want).length == 0, string.concat("anchor accepted; the model expected: ", want));
            next = a;
        } catch Error(string memory reason) {
            require(bytes(want).length > 0, string.concat("rejected an allowed anchor: ", reason));
            require(same(reason, want), string.concat("revert reason '", reason, "' differs from the model's '", want, "'"));
        }
    }

    function checkAnchor(string memory did, address ctl, IssuanceRootRegistryV4.Anchor memory model) internal view {
        IssuanceRootRegistryV4.Anchor memory got = roots.current(did, ctl);
        require(keccak256(abi.encode(got)) == keccak256(abi.encode(model)), "stored anchor differs from the model");
        require(got.epoch == 0 || (got.notBefore < got.notAfter && uint256(got.notAfter) <= uint256(got.notBefore) + MAX_WINDOW), "stored window breaks windowBounds");
    }

    /// Epoch anchors follow controllerOnly, epochIncrement, anchorCadence and windowBounds, over three calls.
    function testFuzz_epochRules(string memory did, address ctl, uint8 regState, uint256[3] memory raws, uint32[3] memory dts) public {
        vm.assume(usable(ctl));
        bool active = setupRecord(did, ctl, regState);
        IssuanceRootRegistryV4.Anchor memory model;
        for (uint256 i = 0; i < 3; i++) {
            vm.warp(block.timestamp + (uint256(dts[i]) % (3 * uint256(MIN_INTERVAL))));
            vm.roll(block.number + 1);
            model = epochStep(did, ctl, active, raws[i], model);
            checkAnchor(did, ctl, model);
        }
    }

    /// An anchor never lands under another controller's record of the same DID string.
    function testFuzz_epochNeedsOwnRecord(string memory did, address owner, address other, uint64 nb) public {
        vm.assume(owner != other && usable(owner) && usable(other));
        vm.assume(nb < type(uint64).max - MAX_WINDOW);
        vm.prank(owner);
        dids.registerDID(did, hex"01", bytes32(0), hex"02", "");
        vm.prank(other);
        try roots.publishEpoch(did, 1, 1, 1, nb, nb + 1, bytes32(0)) {
            revert("anchor accepted for a record the sender does not control");
        } catch Error(string memory reason) {
            require(same(reason, R_CONTROLLER), reason);
        }
        require(roots.current(did, owner).epoch == 0 && roots.current(did, other).epoch == 0, "anchor stored");
    }

    function kemCall(string memory did, address ctl, uint64 nb, uint64 last, bool active, bytes memory pkb) internal returns (bool) {
        string memory want = expectKem(active, last, nb);
        vm.prank(ctl);
        try kems.publishKemKey(did, nb, pkb, hex"aa", hex"bb") {
            require(bytes(want).length == 0, string.concat("KEM key accepted; the model expected: ", want));
            return true;
        } catch Error(string memory reason) {
            require(bytes(want).length > 0, string.concat("rejected an allowed KEM key: ", reason));
            require(same(reason, want), string.concat("revert reason '", reason, "' differs from the model's '", want, "'"));
            return false;
        }
    }

    /// KEM keys follow controllerOnly and kemMonotonic, over three calls.
    function testFuzz_kemRules(string memory did, address ctl, uint8 regState, uint256[3] memory raws, bytes memory pkb) public {
        vm.assume(usable(ctl));
        bool active = setupRecord(did, ctl, regState);
        uint64 last = 0;
        uint64 version = 0;
        for (uint256 i = 0; i < 3; i++) {
            vm.roll(block.number + 1);
            uint64 nb = pickNotBefore(raws[i], last);
            if (kemCall(did, ctl, nb, last, active, pkb)) {
                last = nb;
                version++;
            }
            VerifierKemRegistryV4.KemKey memory k = kems.latest(did, ctl);
            require(k.version == version && k.notBefore == last, "stored KEM version or notBefore differs from the model");
            require(version == 0 || k.kemPkHash == keccak256(pkb), "KEM key hash not stored");
            require(k.notBefore <= MAX_SAFE, "notBefore above 2^53 - 1 stored");
        }
    }
}

/// Handler for the invariant test: random calls on all four registries, each checked against
/// the model; disagreements are counted (a handler call never reverts, so forge keeps going).
contract RegistriesV4Handler is RegistryModelBase {
    DIDRegistryV4 public immutable dids;
    AccreditationRegistryV4 public immutable acc;
    IssuanceRootRegistryV4 public immutable roots;
    VerifierKemRegistryV4 public immutable kems;
    address public immutable governance;

    address[3] internal actors;
    string[3] internal didNames;

    struct GhostAnchor {
        uint64 epoch;
        uint64 notBefore;
        uint64 notAfter;
        uint64 publishedAt;
        uint256 root;
    }

    mapping(bytes32 => bool) public ghostExists;
    mapping(bytes32 => bool) public ghostActive;
    mapping(bytes32 => GhostAnchor) internal ghostAnchor;
    mapping(bytes32 => uint64) public ghostKemNb;
    mapping(bytes32 => uint64) public ghostKemVersion;
    mapping(bytes32 => uint64) public ghostAccSigned;
    mapping(bytes32 => uint64) public ghostAccCount;

    uint256 public calls;
    uint256 public accepted;
    uint256 public mismatches;
    string public firstMismatch;
    // calls the registries accepted, per method (vacuity guard of the invariant test)
    uint256 public acceptedRegister;
    uint256 public acceptedDeactivate;
    uint256 public acceptedAccreditation;
    uint256 public acceptedEpoch;
    uint256 public acceptedKem;

    constructor(DIDRegistryV4 d, AccreditationRegistryV4 a, IssuanceRootRegistryV4 r, VerifierKemRegistryV4 k, address gov) {
        dids = d;
        acc = a;
        roots = r;
        kems = k;
        governance = gov;
        actors[0] = address(0xA1);
        actors[1] = address(0xA2);
        actors[2] = address(0xA3);
        // two DID strings that differ only in a suffix, and the empty string
        didNames[0] = "did:pq:4Cq1";
        didNames[1] = "did:pq:4Cq1x";
        didNames[2] = "";
    }

    function actorAt(uint256 i) external view returns (address) {
        return actors[i % 3];
    }

    function didAt(uint256 i) external view returns (string memory) {
        return didNames[i % 3];
    }

    function anchorOf(bytes32 key) external view returns (GhostAnchor memory) {
        return ghostAnchor[key];
    }

    function note(bool ok, string memory want, string memory got, string memory what) internal {
        calls++;
        bool agree = ok ? bytes(want).length == 0 : (bytes(want).length > 0 && same(got, want));
        if (ok) accepted++;
        if (!agree) {
            mismatches++;
            if (bytes(firstMismatch).length == 0) {
                string memory gotText = "accepted";
                if (!ok) gotText = string.concat("rejected ('", got, "')");
                string memory wantText = "acceptance";
                if (bytes(want).length > 0) wantText = want;
                firstMismatch = string.concat(what, ": registry ", gotText, ", model expected ", wantText);
            }
        }
    }

    function register(uint8 di, uint8 actorIndex, bytes calldata pk, bytes32 nonce) external {
        string memory did = didNames[di % 3];
        address a = actors[actorIndex % 3];
        bytes32 key = keyOf(did, a);
        string memory want = ghostExists[key] ? R_RECORD_UNIQUE : "";
        vm.prank(a);
        try dids.registerDID(did, pk, nonce, hex"5150", "https://x.example") {
            note(true, want, "", "registerDID");
            acceptedRegister++;
            ghostExists[key] = true;
            ghostActive[key] = true;
        } catch Error(string memory reason) {
            note(false, want, reason, "registerDID");
        }
    }

    function deactivate(uint8 di, uint8 actorIndex) external {
        string memory did = didNames[di % 3];
        address a = actors[actorIndex % 3];
        bytes32 key = keyOf(did, a);
        string memory want = ghostActive[key] ? "" : R_DEACTIVATE;
        vm.prank(a);
        try dids.deactivate(did) {
            note(true, want, "", "deactivate");
            acceptedDeactivate++;
            ghostActive[key] = false;
        } catch Error(string memory reason) {
            note(false, want, reason, "deactivate");
        }
    }

    function publishAccreditation(uint8 di, uint8 si, uint256 raw) external {
        string memory did = didNames[di % 3];
        address sender = si % 4 == 0 ? actors[si % 3] : governance;
        bytes32 k = keccak256(bytes(did));
        uint64 s = pickSerial(raw, ghostAccSigned[k]);
        string memory want = expectSerial(sender, governance, ghostAccSigned[k], s);
        vm.prank(sender);
        try acc.publish(did, s, abi.encode(raw), abi.encode(s)) {
            note(true, want, "", "publish accreditation");
            acceptedAccreditation++;
            ghostAccSigned[k] = s;
            ghostAccCount[k] += 1;
        } catch Error(string memory reason) {
            note(false, want, reason, "publish accreditation");
        }
    }

    function publishEpoch(uint8 di, uint8 actorIndex, uint256 raw) external {
        string memory did = didNames[di % 3];
        address a = actors[actorIndex % 3];
        bytes32 key = keyOf(did, a);
        GhostAnchor memory g = ghostAnchor[key];
        GhostAnchor memory n;
        n.epoch = pickEpoch(raw, g.epoch);
        (n.notBefore, n.notAfter) = pickWindow(raw >> 16, block.timestamp);
        n.root = raw % 7919;
        n.publishedAt = uint64(block.timestamp);
        string memory want = expectEpoch(ghostActive[key], g.epoch, g.publishedAt, n.epoch, n.notBefore, n.notAfter, block.timestamp);
        vm.prank(a);
        try roots.publishEpoch(did, n.epoch, n.root, n.root + 1, n.notBefore, n.notAfter, bytes32(raw)) {
            note(true, want, "", "publishEpoch");
            acceptedEpoch++;
            ghostAnchor[key] = n;
        } catch Error(string memory reason) {
            note(false, want, reason, "publishEpoch");
        }
    }

    function publishKem(uint8 di, uint8 actorIndex, uint256 raw) external {
        string memory did = didNames[di % 3];
        address a = actors[actorIndex % 3];
        bytes32 key = keyOf(did, a);
        uint64 nb = pickNotBefore(raw, ghostKemNb[key]);
        string memory want = expectKem(ghostActive[key], ghostKemNb[key], nb);
        vm.prank(a);
        try kems.publishKemKey(did, nb, abi.encode(raw), hex"aa", hex"bb") {
            note(true, want, "", "publishKemKey");
            acceptedKem++;
            ghostKemNb[key] = nb;
            ghostKemVersion[key] += 1;
        } catch Error(string memory reason) {
            note(false, want, reason, "publishKemKey");
        }
    }

    function passTime(uint32 dt) external {
        vm.warp(block.timestamp + (uint256(dt) % (2 * uint256(MIN_INTERVAL))));
        vm.roll(block.number + 1);
    }
}

/// Invariant test: forge calls the handler in random sequences; after each call the registries
/// must agree with the model, call by call and in their stored state.
contract RegistriesV4InvariantTest is RegistryModelBase {
    address internal constant GOV = address(0x60F);
    RegistriesV4Handler internal handler;
    DIDRegistryV4 internal dids;
    AccreditationRegistryV4 internal acc;
    IssuanceRootRegistryV4 internal roots;
    VerifierKemRegistryV4 internal kems;

    function setUp() public {
        dids = new DIDRegistryV4();
        acc = new AccreditationRegistryV4(GOV);
        roots = new IssuanceRootRegistryV4(IDIDRegistryV4(address(dids)), MIN_INTERVAL, MAX_WINDOW);
        kems = new VerifierKemRegistryV4(IDIDRegistryV4(address(dids)));
        handler = new RegistriesV4Handler(dids, acc, roots, kems, GOV);
    }

    /// forge reads this (the StdInvariant interface) to call only the handler.
    function targetContracts() public view returns (address[] memory t) {
        t = new address[](1);
        t[0] = address(handler);
    }

    /// Vacuity guards. (1) test_handlerReachesEveryAcceptance (below) drives the handler's own
    /// pickers and model to an accepted call of every registry method, so a handler or picker bug
    /// that makes a method reject the same way in the model and the contract fails a test
    /// deterministically. (2) forge calls afterInvariant() by name after every invariant run (no
    /// forge-std needed): a run of at least VACUITY_MIN_CALLS model-checked calls must have had a
    /// registration and at least one other call accepted. A per-method requirement in every run
    /// is not used: with about 17 calls per method in a 100-call run, a run without an accepted
    /// accreditation publication (about 22 % of those calls are acceptable) has a probability of
    /// about 1 %, so 256 runs would fail by chance (seen in a development run with another seed).
    uint256 internal constant VACUITY_MIN_CALLS = 50;

    function afterInvariant() public view {
        if (handler.calls() < VACUITY_MIN_CALLS) return;
        require(handler.acceptedRegister() > 0, "vacuity: no registerDID call was accepted in this run");
        require(handler.accepted() > handler.acceptedRegister(), "vacuity: only registrations were accepted in this run");
    }

    /// Every registry method can be accepted through the handler (its pickers and its model).
    function test_handlerReachesEveryAcceptance() public {
        handler.register(0, 0, hex"01", bytes32(0));
        // pickNotBefore(7000, 0): 7000 % 7 == 0, so last + 1 + (7000 >> 8) % 1e6 = 28
        handler.publishKem(0, 0, 7000);
        // pickEpoch(589830, 0): 589830 % 6 == 0, so epoch 1; pickWindow(589830 >> 16 = 9, now): 9 % 9 == 0, the longest valid window
        handler.publishEpoch(0, 0, 589830);
        // governance sender (1 % 4 != 0); pickSerial(10, 0): 10 % 10 == 0, so serial 1
        handler.publishAccreditation(0, 1, 10);
        handler.deactivate(0, 0);
        require(handler.mismatches() == 0, handler.firstMismatch());
        require(handler.acceptedRegister() == 1, "registerDID was not accepted");
        require(handler.acceptedKem() == 1, "publishKemKey was not accepted");
        require(handler.acceptedEpoch() == 1, "publishEpoch was not accepted");
        require(handler.acceptedAccreditation() == 1, "accreditation publication was not accepted");
        require(handler.acceptedDeactivate() == 1, "deactivate was not accepted");
    }

    /// Every accepted or rejected call, with its revert reason, matched the model.
    function invariant_callsMatchModel() public view {
        require(handler.mismatches() == 0, handler.firstMismatch());
    }

    /// Stored state equals the model's ghost state for every (did, controller) and issuer DID.
    function invariant_stateMatchesModel() public view {
        for (uint256 di = 0; di < 3; di++) {
            string memory did = handler.didAt(di);
            AccreditationRegistryV4.Latest memory l = acc.latest(did);
            bytes32 ik = keccak256(bytes(did));
            require(l.serial == handler.ghostAccCount(ik) && l.signedSerial == handler.ghostAccSigned(ik), "accreditation state differs from the model");
            require(l.signedSerial <= MAX_SAFE, "signed serial above 2^53 - 1 stored");
            for (uint256 actorIndex = 0; actorIndex < 3; actorIndex++) {
                address a = handler.actorAt(actorIndex);
                bytes32 key = keyOf(did, a);
                DIDRegistryV4.Record memory r = dids.resolve(did, a);
                require(r.exists == handler.ghostExists(key) && r.active == handler.ghostActive(key), "DID record state differs from the model");
                require(!r.active || r.exists, "active record that does not exist");
                IssuanceRootRegistryV4.Anchor memory an = roots.current(did, a);
                RegistriesV4Handler.GhostAnchor memory g = handler.anchorOf(key);
                require(an.epoch == g.epoch && an.notBefore == g.notBefore && an.notAfter == g.notAfter && an.publishedAt == g.publishedAt && an.root == g.root, "anchor differs from the model");
                require(an.epoch == 0 || r.exists, "anchor without a DID record");
                require(an.epoch == 0 || (an.notBefore < an.notAfter && uint256(an.notAfter) <= uint256(an.notBefore) + MAX_WINDOW), "stored window breaks windowBounds");
                VerifierKemRegistryV4.KemKey memory k = kems.latest(did, a);
                require(k.version == handler.ghostKemVersion(key) && k.notBefore == handler.ghostKemNb(key), "KEM state differs from the model");
                require(k.notBefore <= MAX_SAFE, "KEM notBefore above 2^53 - 1 stored");
                require(k.version == 0 || r.exists, "KEM key without a DID record");
            }
        }
    }
}
