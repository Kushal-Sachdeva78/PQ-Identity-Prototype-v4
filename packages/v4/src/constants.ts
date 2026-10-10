/**
 * v4 constants (docs/v4/V4_DESIGN.md sections 1 and 5). Every value that the circuit
 * also hard-codes is marked CIRCUIT; circuits/credential_auth_v4.circom must match.
 */

/** BN254 scalar field modulus (same as @pqid/common/encoding BN254_P). */
export const BN254_P =
  21888242871839275222246405745257275088548364400416034343698204186575808495617n;

// ---- domain tags (CIRCUIT for STMT_V4, CRED_LEAF_V4, POLICY_V4, IMT_LEAF_V4) ----
export const DOMAIN_ISSUER_KEY = 1001n; // shared with v2/v3
export const DOMAIN_VERIFIER_ID = 1002n; // shared with v2/v3
export const STMT_V4 = 4n;
export const CRED_LEAF_V4 = 1004n;
export const DOMAIN_CRED_TYPE = 1005n;
export const POLICY_V4 = 1006n;
export const IMT_LEAF_V4 = 1007n;

// ---- predicates (CIRCUIT) ----
export const PREDICATE_AGE_GTE = 1n;
export const PREDICATE_AGE_LT = 2n;

/**
 * Standard thresholds the honest wallet answers (DECISIONS D-011), also enforced in
 * the circuit (group G10). CIRCUIT.
 */
export const STANDARD_THRESHOLDS: readonly number[] = [13, 14, 15, 16, 18, 21, 65];

// ---- trees ----
/** Issuance tree depth (same tree as v3). CIRCUIT. */
export const ISSUANCE_DEPTH = 32;
/** Revocation IMT depth (B2 result; DECISIONS D-025). CIRCUIT. */
export const REV_DEPTH = 30;
/** Revocation keys are < 2^251; IMT_MAX is the sentinel upper bound. */
export const REV_KEY_BITS = 251;
export const IMT_MAX = 1n << 251n;

// ---- dates ----
/** Dates are YYYYMMDD integers; every valid date is < 2^27. CIRCUIT (Num2Bits(27)). */
export const DATE_BITS = 27;
export const MIN_DATE = 19000101;
export const MAX_DATE = 99991231;
/** threshold < 2^8. CIRCUIT. */
export const THRESHOLD_BITS = 8;

// ---- protocol timing (DECISIONS D-012, D-014) ----
/** Length of the signed validity window of an issuer epoch statement (s). */
export const EPOCH_WINDOW_SEC = 24 * 3600;
/** Registry-enforced upper bound on an epoch window (s). */
export const MAX_EPOCH_WINDOW_SEC = 24 * 3600;
/** Minimum time between two epochs of one issuer (registry and wallet floor, as v3). */
export const MIN_ANCHOR_INTERVAL_SEC = 3600;
/** Wallet clock tolerance around the verifier-supplied date (s). */
export const WALLET_CLOCK_SKEW_SEC = 300;
/** Maximum lifetime of a governance accreditation statement (s). */
export const MAX_ACCREDITATION_SEC = 30 * 24 * 3600;
/** Default credential lifetime set by the issuer (days). */
export const DEFAULT_CREDENTIAL_DAYS = 90;
/** How long a verifier keeps an open session (ms). */
export const SESSION_TTL_MS = 5 * 60_000;
/**
 * Epoch statements start this many seconds before they are signed, so an anchor made just
 * after a UTC midnight still covers sessions opened before it (session TTL plus wallet
 * clock skew; B5 CIR-2). The registry allows any notBefore below notAfter.
 */
export const EPOCH_BACKDATE_SEC = SESSION_TTL_MS / 1000 + WALLET_CLOCK_SKEW_SEC;

// ---- statement types ----
export const TYPE_DID_POP = "pqid:did-pop:v2";
export const TYPE_ACCREDITATION = "pqid:accreditation:v2";
export const TYPE_EPOCH = "pqid:issuer-epoch:v4";
export const TYPE_VERIFIER_KEM = "pqid:verifier-kem:v1";
export const TYPE_REQUEST = "pqid:request:v4";
export const TYPE_REPLY = "pqid:reply:v4";
export const TYPE_TRANSCRIPT = "pqid:transcript:v4";

/** Default credential type identifier (DECISIONS D-013). */
export const DEFAULT_TYPE_ID = "pqid:type:age-credential:v1";

/** Session KEM (DECISIONS D-015). */
export const KEM_ALG = "ML-KEM-768";
