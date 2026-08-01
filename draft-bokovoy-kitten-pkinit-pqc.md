---
title: "Post-quantum Key Encapsulation with ML-KEM in Public Key Cryptography for Initial Authentication in Kerberos (PKINIT)"
abbrev: "PKINIT-PQC"
docname: draft-bokovoy-kitten-pkinit-pqc-latest
category: std
submissiontype: IETF
ipr: trust200902
area: "Security"
workgroup: "Common Authentication Technology Next Generation"
keyword:
  - Kerberos
  - PKINIT
  - post-quantum
  - ML-KEM
  - ML-DSA
  - KEM

stand_alone: yes
pi:
  toc: yes
  sortrefs: yes
  symrefs: yes
  compact: yes
  subcompact: no

author:
  -
    ins: A. Bokovoy
    name: Alexander Bokovoy
    organization: Red Hat, Inc.
    email: abokovoy@redhat.com

  -
    ins: J. Rische
    name: Julien Rische
    organization: Red Hat, Inc.
    email: jrische@redhat.com

normative:
  RFC2119:
  RFC8174:
  RFC3961:
  RFC4120:
  RFC4556:
  RFC5652:
  RFC5869:
  RFC8009:
  RFC8619:
  RFC8636:
  RFC9881:
  RFC9935:
  FIPS203:
    title: "Module-Lattice-Based Key-Encapsulation Mechanism Standard"
    target: https://doi.org/10.6028/NIST.FIPS.203
    date: 2024-08
    author:
      org: "National Institute of Standards and Technology (NIST)"
    seriesinfo:
      "FIPS PUB": "203"
  SP800-90A:
    title: "Recommendation for Random Number Generation Using Deterministic Random Bit Generators"
    target: https://doi.org/10.6028/NIST.SP.800-90Ar1
    date: 2015-06
    author:
      org: "National Institute of Standards and Technology (NIST)"
    seriesinfo:
      "NIST SP": "800-90A Rev. 1"

  RFC9882:
  I-D.ietf-lamps-pq-composite-kem:
  I-D.ietf-lamps-pq-composite-sigs:

informative:
  RFC5021:
  RFC5349:
  FIPS204:
    title: "Module-Lattice-Based Digital Signature Standard"
    target: https://doi.org/10.6028/NIST.FIPS.204
    date: 2024-08
    author:
      org: "National Institute of Standards and Technology (NIST)"
    seriesinfo:
      "FIPS PUB": "204"
  I-D.rische-kitten-pkinit-crypto-deprec:

--- abstract

This document specifies extensions to the Kerberos PKINIT
pre-authentication mechanism {{RFC4556}} {{RFC8636}} to support
post-quantum key establishment using the Module-Lattice-Based
Key-Encapsulation Mechanism (ML-KEM) algorithms defined in {{FIPS203}}.

The extensions define a new `kemInfo` arm in `PA-PK-AS-REP`, a
`KDCKEMInfo` structure signed by the KDC, HKDF-based AS reply key
derivation (HKDF-SHA-512 for ML-KEM), and downgrade-prevention rules.
The KEM path framework supports multiple KEM algorithms including
ML-KEM, composite ML-KEM algorithms, and future KEM standards.

--- middle

# Introduction

The Kerberos PKINIT pre-authentication mechanism {{RFC4556}} relies on
public-key cryptography for initial authentication.  The Diffie-Hellman
and RSA paths it defines are vulnerable to a cryptographically relevant
quantum computer.  {{RFC5349}} adds Elliptic Curve Diffie-Hellman (ECDH)
support and {{RFC8636}} adds algorithm agility, but neither addresses the
quantum threat.

This document defines a new KEM path in PKINIT that uses Key
Encapsulation Mechanism (KEM) algorithms, in particular the
Module-Lattice-Based Key-Encapsulation Mechanism (ML-KEM) {{FIPS203}}.
Rather than agreeing on a shared secret via a DH exchange, the client
generates an ephemeral KEM key pair and sends the encapsulation key in a
CMS-signed `AuthPack` ({{RFC5652}} Section 5). The KDC encapsulates
against it, signs the ciphertext and algorithm selection in `KDCKEMInfo`,
and returns the signed structure. Both parties derive the AS reply key
using HKDF ({{RFC5869}}).

The design preserves the security properties of the RFC 4556 DH path
(the client's ephemeral key is authenticated by the client's signing
certificate; the KDC's response is authenticated by the KDC's signing
certificate) while providing post-quantum forward secrecy through ML-KEM.

# Requirements Language

{::boilerplate bcp14}

# Protocol Overview

The KEM path is activated when `AuthPack.clientPublicValue` contains an
ML-KEM or composite ML-KEM OID.  The exchange proceeds as follows:

1. The client generates an ephemeral KEM key pair, places the encapsulation
   key in `AuthPack.clientPublicValue`, and sends a signed `AuthPack` in
   `PA-PK-AS-REQ`.

2. The KDC verifies the `AuthPack` signature, encapsulates against the
   client's encapsulation key to obtain a shared secret `ss` and ciphertext
   `kemct`, signs them in a `KDCKEMInfo` structure, and returns
   `PA-PK-AS-REP.kemInfo`.

3. The client verifies the KDC signature, decapsulates to recover `ss`,
   and both parties derive the AS reply key using HKDF-SHA-512 over
   `PkinitKEMSuppPubInfo`.

No DH exchange takes place.  The shared secret is established entirely
through one-sided encapsulation; freshness is provided by the per-request
ephemeral key pair and the echoed nonce.

# KEM Algorithm Interface {#sec-kem-interface}

This specification uses the following generic KEM algorithm interface:

**Encap(ek) → (ss, ct)**: Takes an encapsulation key `ek` and returns a
shared secret `ss` and ciphertext `ct`.

**Decap(dk, ct) → ss**: Takes a decapsulation key `dk` and ciphertext `ct`
and returns the shared secret `ss`.

For ML-KEM ({{FIPS203}}), these correspond to:
- `Encap(ek)` = `ML-KEM.Encaps(ek)` (FIPS 203 Algorithm 17)
- `Decap(dk, ct)` = `ML-KEM.Decaps(dk, ct)` (FIPS 203 Algorithm 18)

The notation `Encap()` and `Decap()` is used throughout this document to
describe the generic KEM path protocol. When implementing ML-KEM specifically,
use the FIPS 203 algorithms. Future specifications extending this framework
to other KEM algorithms MUST define their mapping to this interface.

# Algorithm Identifier Encoding {#sec-alg-id-encoding}

The `parameters` field MUST be absent from all algorithm identifiers used
in this specification.  The source of this requirement differs by
algorithm family:

(a)  ML-KEM and ML-DSA identifiers ({{RFC9935}}, {{RFC9881}}): the
     algorithm parameter set is fully encoded in the OID; no parameters
     field is defined.  Applies to:

     *  `clientPublicValue.algorithm` when carrying an ML-KEM ephemeral key
     *  `KDCKEMInfo.kemAlgorithm`

(b)  HKDF identifiers ({{RFC8619}} Section 3): the OID
     `id-alg-hkdf-with-sha512` has absent parameters by definition.
     Only SHA-512 is defined for the KEM path ({{sec-kdf-oids}}).
     Applies to:

     *  `KDCKEMInfo.kdfAlgorithm`
     *  `AuthPack.supportedKDFs` entries

# New ASN.1 Types {#sec-asn1-types}

## Extended `PA-PK-AS-REP` {#sec-pa-pk-as-rep}

{{RFC4556}}'s `KRB5PkinitTypes` module is `DEFINITIONS EXPLICIT TAGS`,
like the base Kerberos V5 module it extends.  The `PA-PK-AS-REP` arms are
individually overridden to `IMPLICIT OCTET STRING`, carrying DER-encoded
structures; receivers identify the chosen arm by the context tag alone.
This per-field override is why the three arms below (and `kemInfo`,
introduced by this specification) explicitly spell out `IMPLICIT`: it
would not be the module default otherwise.

~~~ asn1
-- KRB5PkinitTypes DEFINITIONS EXPLICIT TAGS ::= BEGIN
PA-PK-AS-REP ::= CHOICE {
    dhSignedData    [0] IMPLICIT OCTET STRING,
        -- RFC 4556: DH/ECDH path
        --   content: KDCDHKeyInfo ({{RFC4556}} Section 3.2.3.1)
    encKeyPack      [1] IMPLICIT OCTET STRING,
        -- RFC 4556: RSA path (deprecated)
        --   content: ReplyKeyPack ({{RFC4556}} Section 3.2.3.2)
    kemInfo         [2] IMPLICIT OCTET STRING,
        -- NEW: KEM path (this specification)
        --   content: KEMRepInfo ({{sec-kemrepinfo}})
    ...
}
~~~

The field name `dhSignedData` matches RFC 4556's actual ASN.1 module;
the informal name `dhInfo` used in some descriptions refers to the same
arm.

Tag `[2]` MUST be verified against the IANA Kerberos PKINIT Parameters
registry before publication to confirm no other extension has claimed it.

Because the module default is `EXPLICIT TAGS`, the new structures
defined below (`KDCKEMInfo`, `PkinitKEMSuppPubInfo`, and the extension
fields added to `AuthPack`) that carry no explicit `IMPLICIT`/`EXPLICIT`
keyword on a given field are tagged `EXPLICIT` by that default —
*not* `IMPLICIT`. Implementations MUST follow the module default for
these fields; only `KEMRepInfo.kemSignedData` (and the `PA-PK-AS-REP`
arms above) are `IMPLICIT`, because they say so explicitly.

## `KEMRepInfo` {#sec-kemrepinfo}

~~~ asn1
-- id-pkinit OID arc (RFC 4556):
-- id-pkinit OBJECT IDENTIFIER ::= { 1 3 6 1 5 2 3 }

id-pkinit-KEMKeyData OBJECT IDENTIFIER ::= { id-pkinit TBD-IANA }

KEMRepInfo ::= SEQUENCE {
    kemSignedData       [0] IMPLICIT OCTET STRING,
        -- CMS SignedData ({{RFC5652}} Section 5):
        --   eContentType = id-pkinit-KEMKeyData
        --   eContent     = DER(KDCKEMInfo)
        --   signerInfos  = KDC signature over KDCKEMInfo
    ...
}
~~~

`eContent` in `kemSignedData` MUST be present (detached signatures are
prohibited).

## `KDCKEMInfo` {#sec-kdckeminfo}

~~~ asn1
KDCKEMInfo ::= SEQUENCE {
    kemAlgorithm    [0] AlgorithmIdentifier,
        -- KEM algorithm and parameter set used (e.g., ML-KEM-768).
        -- MUST match clientPublicValue.algorithm OID.
    kemct           [1] OCTET STRING,
        -- KEM ciphertext produced by Encap(ek) (see {{sec-kem-interface}}).
        -- Algorithm-specific sizes: see {{sec-mlkem-sizes}} for ML-KEM.
    kdfAlgorithm    [2] AlgorithmIdentifier,
        -- HKDF variant selected from supportedKDFs (fixes RFC 8636
        -- unauthenticated selection flaw).
    nonce           [3] INTEGER (0..4294967295) OPTIONAL,
        -- When present, MUST equal pkAuthenticator.nonce from the
        -- client's AS-REQ. Implementations SHOULD include this field.
        -- Future KEM variants and hybrid DH+KEM modes MAY omit it if
        -- alternative freshness mechanisms are defined by their
        -- respective specifications.
    serverNonce     [4] OCTET STRING OPTIONAL,
        -- Reserved for future hybrid DH+KEM modes. Analogous to
        -- RFC 4556 serverDHNonce. MUST be absent in pure ML-KEM.
    ...
}
~~~

`kemAlgorithm` makes `KDCKEMInfo` self-describing and provides signed
confirmation that the KDC processed the correct algorithm (verified in
{{sec-client-processing}} step 5), avoiding implicit inference from
`kemct` length alone.

## Extended `AuthPack` {#sec-authpack}

~~~ asn1
AuthPack ::= SEQUENCE {
    pkAuthenticator     [0] PKAuthenticator,
    clientPublicValue   [1] SubjectPublicKeyInfo OPTIONAL,
        -- DH/ECDH path: ephemeral DH/ECDH public key (RFC 4556).
        -- KEM path:     ephemeral ML-KEM encapsulation key, encoded per
        --               RFC 9935.
        -- RSA path:     MUST be absent.
    supportedCMSTypes   [2] SEQUENCE OF AlgorithmIdentifier OPTIONAL,
        -- Used in RSA path only (deprecated; see RFC 4556 Section 3.1.4).
    clientDHNonce       [3] DHNonce OPTIONAL,
        -- Pure KEM path (this specification): MUST be absent when
        -- clientPublicValue contains a KEM algorithm OID (see
        -- {{sec-asn1-types}}). Future hybrid DH+KEM specifications MAY define
        -- use of this field alongside KEM OIDs.
    supportedKDFs       [4] SEQUENCE OF AlgorithmIdentifier OPTIONAL,
        -- KDFAlgorithmId is AlgorithmIdentifier; no separate type is
        -- defined.
        -- KEM path: HKDF algorithm OIDs ({{sec-kdf-oids}}). Only
        --   HKDF-SHA-512 is defined for the KEM path; this field
        --   SHOULD contain id-alg-hkdf-with-sha512. If absent when a
        --   KEM OID is in clientPublicValue, HKDF-SHA-512 is assumed.
        -- DH/ECDH path: DH-KDF algorithm OIDs (RFC 8636).
    ...
}
~~~

## `PkinitKEMSuppPubInfo` {#sec-supppubinfo}

~~~ asn1
-- Types imported from RFC 4120 (KerberosV5 module): Int32

PkinitKEMSuppPubInfo ::= SEQUENCE {
    enctype         [0] Int32,
        -- Kerberos enctype of the AS reply key.
    as-REQ          [1] OCTET STRING,
        -- DER(AS-REQ).
    kemSignedData   [2] OCTET STRING,
        -- DER(KEMRepInfo.kemSignedData): the KDC-signed KDCKEMInfo.
    ...
}
~~~

# Mode Selection {#sec-mode-selection}

The exchange mode is determined by the algorithm OID in
`clientPublicValue`:

| `clientPublicValue` | OID type | Mode |
|:---|:---|:---|
| Absent | — | RSA path (`encKeyPack`); deprecated by {{I-D.rische-kitten-pkinit-crypto-deprec}} |
| Present | DH or ECDH OID | DH/ECDH path ({{RFC4556}} / {{RFC8636}}) |
| Present | ML-KEM or composite ML-KEM OID | KEM path (this specification) |
| Present | Unrecognized OID | Error (see {{sec-downgrade}}); MUST NOT fall back to RSA path |
{: #tab-mode-selection title="Mode selection by clientPublicValue OID"}

For the pure KEM path defined in this specification, when
`clientPublicValue` contains a KEM OID and `clientDHNonce` is also
present, the KDC MUST return `KDC_ERR_PREAUTH_FAILED`.  Future hybrid
DH+KEM specifications may define different nonce semantics and relax this
requirement.

When present, `supportedKDFs` MUST contain only KDFs applicable to the
path indicated by `clientPublicValue.algorithm`: HKDF algorithm OIDs
({{sec-kdf-oids}}) for the KEM path, or DH-KDF algorithm OIDs per
{{RFC8636}} for the DH/ECDH path.

# KEM Path Operation {#sec-kem-operation}

## Client Request Construction {#sec-client-request}

1. Generate a fresh ephemeral KEM key pair `(ek, dk)` for the chosen
   algorithm using a cryptographically secure pseudorandom number
   generator (CSPRNG).  The security of the KEM path depends entirely on
   the unpredictability of `dk` (for ML-KEM CSPRNG requirements, see
   {{sec-mlkem-csprng}}).

2. Encode `ek` as `SubjectPublicKeyInfo` and place it in
   `AuthPack.clientPublicValue`.  `parameters` MUST be absent.  For
   ML-KEM, encoding follows {{RFC9935}}.

3. Set `supportedKDFs` to `{ id-alg-hkdf-with-sha512 }`.  If omitted,
   HKDF-SHA-512 is assumed.

4. Wrap `AuthPack` as the `eContent` of a CMS `SignedData` ({{RFC5652}}
   Section 5) per {{RFC4556}} Section 3.2.2 and sign with the client's
   signing certificate.  For full quantum resistance, the client SHOULD
   use an ML-DSA certificate ({{RFC9881}}); traditional ECDSA and RSA
   certificates are permitted during the transition period.  When
   signing with ML-DSA, the CMS `SignedData` MUST conform to
   {{RFC9882}} Section 3 (Signed-Data Conventions).

The ephemeral encapsulation key `ek` is authenticated by the client's
signing certificate via `AuthPack.SignedData` ({{RFC5652}} Section 5.2),
following the {{RFC4556}} DH path model. No separate encapsulation
certificate is required.

## KDC Response Construction {#sec-kdc-response}

1. Detect the KEM algorithm OID in `clientPublicValue.algorithm`.

2. Check whether the algorithm is supported and meets the KDC's security
   policy (per {{RFC4556}} Section 3.2.2):

   a.  If the algorithm OID is not recognized or not implemented, return
       `KDC_ERR_EPHEMERAL_KEY_PARAMS_NOT_ACCEPTED` (error code 65) with
       `TD-EPHEMERAL-KEY-PARAMETERS-DATA` listing supported algorithms;
       stop.

   b.  If the algorithm does not satisfy the KDC's security policy, return
       `KDC_ERR_EPHEMERAL_KEY_PARAMS_NOT_ACCEPTED` (error code 65) with
       `TD-EPHEMERAL-KEY-PARAMETERS-DATA` listing acceptable algorithms;
       stop.

3. Select a KDF from `supportedKDFs` that is approved for the KEM
   algorithm (see {{sec-kdf-oids}}).  If `supportedKDFs` is absent,
   default to `id-alg-hkdf-with-sha512`.  If no approved KDF can be
   selected, return `KDC_ERR_NO_ACCEPTABLE_KDF` (error code 100,
   {{RFC8636}}); stop.

4. Call `Encap(ek)` → `(ss, kemct)` using the selected algorithm (see
   {{sec-kem-interface}}).  Exactly one encapsulation MUST be performed per
   exchange; the resulting `(ss, kemct)` pair MUST be used in all
   subsequent steps (for ML-KEM specifics, see {{sec-mlkem-encap}}).

5. Build `KDCKEMInfo`:

   *  `kemAlgorithm` = OID from `clientPublicValue.algorithm` (echoed back)
   *  `kemct` = the ciphertext from step 4
   *  `kdfAlgorithm` = selected HKDF OID
   *  `nonce` = `pkAuthenticator.nonce` from the client's request
      (SHOULD be included; see {{sec-kdckeminfo}})

6. Sign `KDCKEMInfo` using CMS SignedData ({{RFC5652}} Section 5).
   ML-DSA is RECOMMENDED; when used, the CMS `SignedData` MUST
   conform to {{RFC9882}} Section 3.  Place in `kemSignedData`.
   `eContent` MUST be present.  Step 7 MUST follow step 6 because
   `PkinitKEMSuppPubInfo.kemSignedData` is set to the DER encoding of
   `KEMRepInfo.kemSignedData` produced in this step.

7. Derive the AS reply key from `ss` per {{sec-kdf}}.  The KDC uses it to
   encrypt the AS-REP `enc-part`.

8. Return `PA-PK-AS-REP.kemInfo` containing `KEMRepInfo`.

## Client Response Processing {#sec-client-processing}

The client MUST perform the following steps in order.  On any abort the
client MUST erase `dk` before returning.

1. **Verify KDC signature** over `kemSignedData`.  Abort if invalid.

2. **Enforce KDC signing algorithm**: If the client used a post-quantum
   signing certificate, verify that the KDC's `kemSignedData` signature
   uses a quantum-resistant algorithm per {{sec-downgrade}}.  Abort if
   the KDC signed with a traditional algorithm.

3. **Verify `serverNonce` is absent**: `KDCKEMInfo.serverNonce` MUST NOT
   be present in pure ML-KEM exchanges defined by this specification.
   Abort if present.

4. **Extract and verify nonce**: If `KDCKEMInfo.nonce` is present, it
   MUST equal `pkAuthenticator.nonce`.  Abort if not.  If absent,
   implementations MUST verify freshness through alternative means
   (e.g., timestamp in `PKAuthenticator`); future KEM specifications
   MUST define which mechanism applies when nonce is omitted.

5. **Verify echoed algorithm**: `KDCKEMInfo.kemAlgorithm` MUST exactly
   match the algorithm OID in the client's own
   `clientPublicValue.algorithm`.  Abort if they differ.  This confirms
   the KDC did not substitute a different algorithm.

6. **Validate `kemct` length**: the byte length of `KDCKEMInfo.kemct`
   MUST match the fixed ciphertext size for `KDCKEMInfo.kemAlgorithm`
   (see {{sec-mlkem-sizes}} for ML-KEM sizes).  Abort if not.  KEM
   algorithms MUST NOT be called on incorrectly-sized ciphertexts.

7. **Decapsulate**: `ss = Decap(dk, KDCKEMInfo.kemct)`
   using the algorithm in `KDCKEMInfo.kemAlgorithm`.  Erase `dk`
   immediately after this call completes, before any further processing.

8. **Derive reply key** from `ss` per {{sec-kdf}}.  Use this key to
   decrypt the AS-REP `enc-part`.

9. **Confirm `dk` erasure**.  The ephemeral decapsulation key MUST have
   been erased in step 7 and MUST NOT be retained.

Steps 1–6 MUST complete before step 7.  Decapsulation MUST NOT be called
on an unauthenticated ciphertext.

## KDC Certificate Validation {#sec-cert-validation}

The KDC certificate validation rules of {{RFC4556}} Section 3.2.3 apply
unchanged to `kemSignedData`.  The client uses the same trust anchors and
validation procedure as for the DH path.

# AS Reply Key Derivation {#sec-kdf}

## HKDF OIDs {#sec-kdf-oids}

The KEM path uses {{RFC8636}}'s KDF negotiation mechanism via
`supportedKDFs`. For ML-KEM and composite ML-KEM, this specification
approves only HKDF-SHA-512:

~~~ asn1
id-alg-hkdf-with-sha512 OBJECT IDENTIFIER ::=
    { 1 2 840 113549 1 9 16 3 30 }
~~~

| OID | Hash | Conformance for ML-KEM |
|:---|:---|:---|
| `id-alg-hkdf-with-sha512` | SHA-512 | MUST implement |
{: #tab-kdf-oids title="Approved KDFs for ML-KEM"}

When `clientPublicValue.algorithm` contains an ML-KEM or composite ML-KEM
OID, the KDC selects a KDF from `supportedKDFs` that appears in the
approved list above. If `supportedKDFs` is absent, the KDC defaults to
`id-alg-hkdf-with-sha512`. If `supportedKDFs` is present but contains no
approved KDF, the KDC returns `KDC_ERR_NO_ACCEPTABLE_KDF` per
{{sec-kdc-response}} step 3; it MUST NOT silently substitute a KDF the
client did not offer.

## Derivation {#sec-kdf-derivation}

~~~
reply_key_material = HKDF-SHA-512(
    IKM  = ss,
        -- ML-KEM.Decaps output (see {{sec-mlkem-sizes}} for ML-KEM sizes)
    salt = <not provided>,
        -- defaults to HashLen zero bytes (RFC 5869 Section 2.2);
        -- ss is uniformly random so extraction is unnecessary
    info = DER(PkinitKEMSuppPubInfo),
    L    = <random-to-key input length for enctype>
)
reply_key = random-to-key(reply_key_material)
    -- per RFC 3961 Section 3
~~~

`L` is the `random-to-key` input string length for the Kerberos enctype
in `PkinitKEMSuppPubInfo.enctype`, as defined in the enctype's
specification:

| Enctype | L |
|:---|:---|
| `aes128-cts-hmac-sha256-128` ({{RFC8009}}) | 16 bytes |
| `aes256-cts-hmac-sha384-192` ({{RFC8009}}) | 32 bytes |
{: #tab-kdf-length title="random-to-key input lengths by enctype"}

For these enctypes `random-to-key` is the identity function.  Other
enctypes use the key-generation seedlength from their {{RFC3961}} crypto
profile.

`PkinitKEMSuppPubInfo.kemSignedData` is set to
`DER(KEMRepInfo.kemSignedData)`: the KDC-signed `KDCKEMInfo` only, not
the full `PA-PK-AS-REP`.  This avoids a circular dependency: the full
response cannot be included in the context used to derive the key that
protects it.

The value `reply_key` produced by this derivation IS the AS reply key
used to encrypt the Kerberos AS-REP `enc-part`.  Both the KDC and the
client independently derive the same value from `ss` using the KDF
algorithm and context recorded in `PkinitKEMSuppPubInfo`.  The reply key
is never transmitted; both parties arrive at it through independent
computation.

# Error Handling {#sec-errors}

## Proactive Advertisement {#sec-proactive-adv}

{{RFC4556}} Section 3.4 specifies that the `padata-value` of the
`PA_PK_AS_REQ` element in the `KDC_ERR_PREAUTH_REQUIRED` `METHOD-DATA`
MUST be empty, and that "future extensions to this protocol may specify
other data to send instead of an empty OCTET STRING."  This specification
defines such an extension.

A KDC SHOULD populate the `padata-value` of the `PA_PK_AS_REQ` element
with the DER encoding of `PA-PK-AS-REQ-Hint`:

~~~ asn1
PA-PK-AS-REQ-Hint ::= SEQUENCE {
    ephemeralKeyParameters [0] SEQUENCE OF AlgorithmIdentifier
                                   OPTIONAL,
        -- DH, ECDH, ML-KEM, and composite ML-KEM algorithms
        -- the KDC supports, in decreasing preference order.
    ...
}
~~~

Clients that understand `PA-PK-AS-REQ-Hint` SHOULD use the
`ephemeralKeyParameters` field to select an ephemeral key algorithm for
their first PKINIT attempt.  Clients that do not understand this extension
will ignore the `padata-value` as required by {{RFC4556}} Section 3.4.

## Ephemeral Key Parameter Errors {#sec-ephemeral-key-errors}

When the algorithm and parameter set in `clientPublicValue.algorithm` does
not satisfy the KDC's security policy, the KDC returns:

~~~
KDC_ERR_EPHEMERAL_KEY_PARAMS_NOT_ACCEPTED    65
~~~

This error code is a renamed and expanded version of
`KDC_ERR_DH_KEY_PARAMETERS_NOT_ACCEPTED` from {{RFC4556}}, which already
covers DH ({{RFC4556}}) and ECDH ({{RFC5349}}). The error code number (65)
is reused; this specification extends the scope to also cover ML-KEM and
composite ML-KEM.

This error is returned when:

* The algorithm OID is not recognized or not implemented by the KDC
* The algorithm does not meet the KDC's security requirements

The KDC SHOULD include `TD-EPHEMERAL-KEY-PARAMETERS-DATA` in the error
response.  `TD-EPHEMERAL-KEY-PARAMETERS` (formerly `TD-DH-PARAMETERS`)
reuses the existing IANA integer from {{RFC4556}} Section 3.2.2.  The
ASN.1 encoding is unchanged; {{RFC5349}} extended the scope to include
ECDH, and this specification further extends it to include ML-KEM and
composite ML-KEM parameter sets.

~~~ asn1
TD-EPHEMERAL-KEY-PARAMETERS-DATA ::= SEQUENCE OF AlgorithmIdentifier
~~~

After receiving this error, the client follows {{RFC4556}} Section 3.2.2
retry behavior, selecting a different parameter set from
`TD-EPHEMERAL-KEY-PARAMETERS-DATA` that satisfies the client's security
policy. If no mutually acceptable parameter set exists, the exchange
MUST be terminated.

## KEM Path Errors {#sec-kem-errors}

When `clientPublicValue` contains a KEM OID, the KDC MUST NOT return DH
digest negotiation errors (`KDC_ERR_DIGEST_IN_SIGNED_DATA_NOT_ACCEPTED`,
`KDC_ERR_DIGEST_IN_CERT_NOT_ACCEPTED`). The only applicable error for
parameter negotiation failure on the KEM path is
`KDC_ERR_EPHEMERAL_KEY_PARAMS_NOT_ACCEPTED` ({{sec-ephemeral-key-errors}}).

# Downgrade Prevention {#sec-downgrade}

When a client uses a post-quantum certificate (e.g., ML-DSA per {{RFC9881}},
composite ML-DSA per {{I-D.ietf-lamps-pq-composite-sigs}}, or future
quantum-resistant signature algorithms) and sends a post-quantum KEM
encapsulation key (ML-KEM or composite ML-KEM) in `clientPublicValue`, the
following rules apply:

*  The client MUST NOT fall back to traditional key-establishment algorithms
   (DH, ECDH, RSA).  The client MAY retry with a different post-quantum KEM
   algorithm from {{sec-kem-errors}}.  If no post-quantum KEM is available,
   the client MUST fail the authentication attempt.

*  The client MUST verify that the KDC's `kemSignedData` signature was
   produced using a quantum-resistant algorithm (e.g., ML-DSA per
   {{RFC9882}}, composite ML-DSA per
   {{I-D.ietf-lamps-pq-composite-sigs}}, or future quantum-resistant
   signature algorithms).  If the KDC signed with a traditional algorithm
   (RSA, ECDSA), the client MUST reject the response.

These rules ensure that quantum-resistant authentication and key
establishment are paired end-to-end when the client's certificate indicates
a commitment to post-quantum security.  See {{sec-security}} for further
discussion.

Clients using traditional certificates MAY fall back from post-quantum KEM
to traditional key establishment for backward compatibility with
non-upgraded KDCs.  The security considerations regarding unauthenticated
error messages in {{RFC4556}} Section 5 apply.

# Algorithm Requirements {#sec-algorithms}

## KEM Algorithms {#sec-kem-algs}

### Pure ML-KEM Algorithms {#sec-pure-mlkem}

| Algorithm | OID | NIST Category | Conformance |
|:---|:---|:---|:---|
| ML-KEM-512 | 2.16.840.1.101.3.4.4.1 | 1 | MAY |
| ML-KEM-768 | 2.16.840.1.101.3.4.4.2 | 3 | MUST implement |
| ML-KEM-1024 | 2.16.840.1.101.3.4.4.3 | 5 | SHOULD |
{: #tab-pure-mlkem title="Pure ML-KEM algorithm requirements"}

### Composite ML-KEM Algorithms {#sec-composite-kem}

| Algorithm | OID | NIST Category | Conformance |
|:---|:---|:---|:---|
| id-MLKEM768-ECDH-P256-SHA3-256 | 1.3.6.1.5.5.7.6.59 | 3 | SHOULD |
| id-MLKEM768-X25519-SHA3-256 | 1.3.6.1.5.5.7.6.58 | 3 | MAY |
| id-MLKEM1024-ECDH-P384-SHA3-256 | 1.3.6.1.5.5.7.6.63 | 5 | SHOULD |
{: #tab-composite-kem title="Composite ML-KEM algorithm requirements"}

Composite algorithms are defined in
{{I-D.ietf-lamps-pq-composite-kem}}.

## Client Algorithm Selection {#sec-client-alg-selection}

As with {{RFC4556}} DH path algorithm selection, the client selects which
KEM algorithm to use based on local policy. Algorithm selection is
implementation-defined.

If the client receives proactive advertisement ({{sec-proactive-adv}}) and
supports none of the advertised algorithms, it MUST fail the authentication
attempt rather than trying an unadvertised algorithm.

## KDC Security Policy {#sec-min-security}

As with {{RFC4556}} Section 3.2.2, the KDC enforces a security policy for
ephemeral key algorithms. The specific policy is implementation-defined.

For ML-KEM, implementations MAY use NIST security categories as a basis for
policy decisions:

| Category | Algorithm | Post-quantum bit security |
|:---|:---|:---|
| 1 | ML-KEM-512 | 128 bits |
| 3 | ML-KEM-768 | 192 bits |
| 5 | ML-KEM-1024 | 256 bits |
{: #tab-security-levels title="NIST security categories for ML-KEM"}

NIST recommends ML-KEM-768 (Category 3) as the default parameter set, as it
provides a large security margin at a reasonable performance cost. Composite
parameter sets combining ML-KEM with traditional algorithms provide the
security category of their ML-KEM component for post-quantum resistance.


# Message Size Considerations {#sec-message-size}

An `AuthPack` with an ephemeral ML-KEM-768 encapsulation key (1184 bytes,
see {{sec-mlkem-sizes}}) signed with ML-DSA-65 (3309-bytes signature
{{FIPS204}}) will exceed UDP datagram limits.  TCP transport ({{RFC5021}})
is REQUIRED for ML-KEM PKINIT.  All Kerberos infrastructure (KDCs, clients,
firewalls) MUST support TCP Kerberos before enabling ML-KEM PKINIT.

# ML-KEM-Specific Considerations {#sec-mlkem}

This section captures behavior specific to ML-KEM ({{FIPS203}}).  When
this specification is extended to other KEM algorithms, per-algorithm
sections following this structure SHOULD be added.  The core protocol
defined in {{sec-kem-interface}} through {{sec-errors}} is intentionally
algorithm-agnostic; ML-KEM details are isolated here following the model
of {{RFC3961}}.

## Key and Ciphertext Sizes {#sec-mlkem-sizes}

All sizes are fixed by {{FIPS203}}; no variability is permitted.

| Algorithm | Encapsulation key | Ciphertext | Shared secret |
|:---|:---|:---|:---|
| ML-KEM-512 | 800 bytes | 768 bytes | 32 bytes |
| ML-KEM-768 | 1184 bytes | 1088 bytes | 32 bytes |
| ML-KEM-1024 | 1568 bytes | 1568 bytes | 32 bytes |
{: #tab-mlkem-sizes title="ML-KEM fixed key and ciphertext sizes"}

The client MUST validate `KDCKEMInfo.kemct` length against these values
before calling Decapsulate ({{sec-client-processing}} step 6).
{{FIPS203}} does not define behavior for `ML-KEM.Decaps` on
incorrectly-sized input.

## CSPRNG Requirement {#sec-mlkem-csprng}

Both ML-KEM key generation and encapsulation MUST use a cryptographically
secure pseudorandom number generator (CSPRNG) satisfying the requirements
of {{FIPS203}} Section 3.3.  The security of the KEM path depends on:

- Client-side: the unpredictability of the ephemeral decapsulation key `dk`
  during key generation.
- KDC-side: the unpredictability of the randomness used during
  `ML-KEM.Encaps(ek)`, which produces the shared secret `ss` and ciphertext
  `kemct`.

A weak or predictable RNG on either side compromises the AS reply key.

## Encapsulation and Decapsulation {#sec-mlkem-encap}

KDC:
:  `(ss, kemct) = ML-KEM.Encaps(ek)` per {{sec-kdc-response}} step 4.

Client:
:  `ss = ML-KEM.Decaps(dk, kemct)` per {{sec-client-processing}} step 7,
   followed by immediate `dk` erasure.

The shared secret `ss` is 32 bytes for all three ML-KEM variants.

# Security Considerations {#sec-security}

## Quantum Resistance

The KEM path achieves post-quantum confidentiality only when both the KEM
algorithm and the KDC signing algorithm are quantum-resistant.  Using
ML-KEM with a traditional ECDSA or RSA signing certificate provides PQC key
establishment but not PQC authentication; an adversary with a quantum
computer could impersonate the KDC by forging its traditional signature.
Deployers seeking full quantum resistance MUST use ML-DSA ({{RFC9881}})
or a composite ML-DSA variant ({{I-D.ietf-lamps-pq-composite-sigs}}) for
KDC signing.  When the client itself uses a post-quantum signing
certificate, the downgrade prevention rules in {{sec-downgrade}} require the
client to enforce quantum-resistant KDC authentication as well, ensuring
end-to-end quantum resistance.

## Ephemeral Decapsulation Key Hygiene

The ephemeral decapsulation key `dk` MUST be erased as soon as
decapsulation completes ({{sec-client-processing}} step 7).  Failure to
erase `dk` negates forward secrecy: an attacker who later recovers
`dk` can recompute `ss` and derive the AS reply key for any recorded
exchange that used the corresponding `ek`.

## Authenticated KDF Inputs

{{RFC8636}} leaves the KDF algorithm unprotected: a man-in-the-middle
could modify the `kdfAlgorithm` field before the client processes the
response.  This specification places `kdfAlgorithm` inside the
KDC-signed `KDCKEMInfo`, making it authenticated.  Clients MUST NOT
derive a reply key using an algorithm not present in the signed
structure.

## Unauthenticated Error Messages

The security considerations in {{RFC4556}} Section 5 regarding unauthenticated
`KRB-ERROR` messages apply to `TD-EPHEMERAL-KEY-PARAMETERS-DATA`. Clients MUST
enforce their configured security policy regardless of advertised algorithms.

## Algorithm Downgrade Prevention

The downgrade prevention rules in {{sec-downgrade}} are mandatory and
unconditional.  A client that allows a fallback from the KEM path to the
DH/RSA path on receiving a traditional response exposes the session to an
active attacker who can exploit a traditional-path vulnerability.

## Nonce Generation

The nonce in `PKAuthenticator` provides replay protection. Implementations
MUST generate nonces from a Deterministic Random Bit Generator (DRBG)
approved by {{SP800-90A}}. Counter-based or predictable nonces compromise
replay protection.

# IANA Considerations {#sec-iana}

## New Kerberos Error Code

IANA is requested to assign a new Kerberos Message Error Code in the
"Kerberos Message Error Codes" sub-registry of the "Kerberos Parameters"
registry:

| Value | Old Name | New Name | Reference |
|:---|:---|:---|:---|
| 65 | `KDC_ERR_DH_KEY_PARAMETERS_NOT_ACCEPTED` | `KDC_ERR_EPHEMERAL_KEY_PARAMS_NOT_ACCEPTED` | {{RFC4556}}, This document |
{: #tab-iana-error title="Renamed Kerberos error code"}

## New PKINIT OID

IANA is requested to assign a new object identifier under the PKINIT OID
arc (`id-pkinit`, `1.3.6.1.5.2.3`) in the "SMI Security for PKIX
Module Identifier" registry:

| Decimal | Description | Reference |
|:---|:---|:---|
| TBD | `id-pkinit-KEMKeyData` | This document |
{: #tab-iana-oid title="New PKINIT OID assignment"}

## Update to Kerberos Pre-Authentication Data Types Registry

IANA is requested to update the description of the existing entry for
`TD-DH-PARAMETERS` in the "Kerberos Pre-Authentication Data Types"
sub-registry of the "Kerberos Parameters" registry:

Old description:
: "Typed data for `KDC_ERR_KEY_TOO_WEAK`; contains a list of acceptable
  Diffie-Hellman algorithm identifiers."

New name and description:
: `TD-EPHEMERAL-KEY-PARAMETERS`, "Typed data for
  `KDC_ERR_EPHEMERAL_KEY_PARAMS_NOT_ACCEPTED` and `KDC_ERR_KEY_TOO_WEAK`; contains
  a list of acceptable ephemeral key-establishment algorithm identifiers,
  including DH, ECDH, ML-KEM, and composite ML-KEM algorithms."

The integer value and ASN.1 encoding (`SEQUENCE OF AlgorithmIdentifier`)
are unchanged.  No new integer allocation is required.

--- back

# Acknowledgements
{:numbered="false"}

The authors thank the IETF KITTEN and LAMPS working groups for
discussion of post-quantum PKINIT approaches, and the NIST team for
{{FIPS203}} and {{FIPS204}}.
