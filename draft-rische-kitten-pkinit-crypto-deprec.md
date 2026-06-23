---
stand_alone: true
ipr: trust200902
cat: std
submissiontype: IETF
area: Security
wg: Common Authentication Technology Next Generation

docname: draft-rische-kitten-pkinit-crypto-deprec-latest
updates: 4556, 5349, 8636

title: >
  Deprecation of Outdated Cryptographic Algorithms and Parameters in
  Kerberos PKINIT
abbrev: PKINIT-CypDpr
lang: en
kw:
  - Kerberos
  - PKINIT
  - cryptographic deprecation
  - SHA-1
  - Diffie-Hellman
  - MODP
  - RSA

author:
- ins: J. Rische
  name: Julien Rische
  org: Red Hat, Inc.
  street: 23-25 rue Delarivière Lefoullon
  city: Puteaux
  code: "92800"
  country: France
  email: jrische@redhat.com

normative:
  RFC3526:
  RFC4120:
  RFC4556:
  RFC5349:
  RFC5754:
  RFC8636:

informative:
  RFC2409:
  RFC2412:
  RFC7696:
  RFC8070:
  RFC9155:
  I-D.irtf-cfrg-rsa-guidance:
    title: >
      Implementation Guidance for the PKCS#1 RSA Cryptography
      Specification
    author:
    - name: Hubert Kario
      org: Red Hat, Inc.
    date: 2026-03
    seriesinfo:
      Internet-Draft: draft-irtf-cfrg-rsa-guidance-08
  MS-PKCA:
    title: >
      Public Key Cryptography for Initial Authentication (PKINIT) in
      Kerberos Protocol
    author:
    - org: Microsoft Corporation
    target: https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-pkca/
    date: 2025

--- abstract

This document deprecates several outdated cryptographic algorithms and
parameters from the Kerberos PKINIT specification (RFC 4556) and its
extensions (RFC 5349, RFC 8636).  Specifically, it deprecates the RSA
key transport mechanism for reply key delivery, the Diffie-Hellman MODP
group 2 (1024-bit) parameter, the SHA-1-based octetstring2key key
derivation function, and the sha1WithRSAEncryption CMS signature
algorithm.  It also defines a new `paChecksum2` field in the
`PKAuthenticator` structure to provide checksum algorithm agility.

This document updates RFC 4556, RFC 5349, and RFC 8636.

--- middle

# Introduction

Since the publication of the initial PKINIT specification in {{RFC4556}},
significant advances in cryptanalysis and computing power have rendered
several of its cryptographic elements inadequate for current use.
BCP 201 {{RFC7696}} stresses the importance of proactively deprecating
weakened algorithms.  This document addresses five such elements.

The RSA key transport mechanism defined in {{RFC4556}} Section 3.2.3.2
relies on RSAES-PKCS-v1_5, which has been subject to Bleichenbacher-
style adaptive chosen-ciphertext attacks since 1998 and to numerous
side-channel attacks documented in {{I-D.irtf-cfrg-rsa-guidance}}.
It also prevents the client from contributing entropy to the session
key.

The 1024-bit Diffie-Hellman MODP group 2 ({{RFC2409}} Section 6.2,
{{RFC2412}} Appendix E.2), mandatory in {{RFC4556}}, provides at most
approximately 80 bits of security strength.  NIST has deprecated
1024-bit discrete-logarithm key sizes and major cryptographic libraries
such as OpenSSL no longer support this group, creating practical
interoperability failures in PKINIT deployments.

SHA-1 has been demonstrably broken for collision resistance since 2017.
NIST disallowed SHA-1 for digital signature generation in 2013, and
{{RFC9155}} formally deprecated it in TLS 1.2.  Three elements of the
PKINIT protocol depend on SHA-1: the `sha1WithRSAEncryption` CMS
signature algorithm mandated in {{RFC4556}} Section 3.2.2, the
`octetstring2key()` key derivation function in {{RFC4556}}
Section 3.2.3.1, and the hardwired SHA-1 checksum in the `paChecksum`
field of `PKAuthenticator`.  {{RFC8636}} introduced negotiable KDFs and
acknowledged the `paChecksum` limitation but left both the KDF
negotiation and the checksum algorithm as optional.

This specification:

1. Deprecates the RSA key transport mechanism ({{sec-rsa-deprec}}).
2. Deprecates MODP group 2 ({{sec-modp-deprec}}).
3. Makes the `supportedKDFs` field mandatory and deprecates the SHA-1
   KDF ({{sec-kdf-deprec}}).
4. Deprecates `sha1WithRSAEncryption` and `ecdsa-with-SHA1` in CMS
   signatures ({{sec-sig-deprec}}).
5. Defines `paChecksum2` for checksum algorithm agility
   ({{sec-pachecksum2}}).

## Requirements Language

{::boilerplate bcp14-tagged}

# RSA Key Transport {#sec-rsa-deprec}

Implementations conforming to this specification MUST NOT use the RSA
key transport mechanism (the `encKeyPack` choice of `PA-PK-AS-REP`)
defined in {{RFC4556}} Section 3.2.3.2.

Clients conforming to this specification:

* MUST include the `clientPublicValue` field in the `AuthPack`
  structure, containing a Diffie-Hellman or ECDH public key.

* MUST NOT omit `clientPublicValue` in order to request RSA key
  transport.

KDCs conforming to this specification:

* MUST reply using the `dhInfo` choice in `PA-PK-AS-REP` (the
  Diffie-Hellman key delivery method described in {{RFC4556}}
  Section 3.2.3.1 or the ECDH method described in {{RFC5349}}).

* MUST NOT reply using the `encKeyPack` choice in `PA-PK-AS-REP`.

* SHOULD return `KDC_ERR_PREAUTH_FAILED` if a client request
  omits the `clientPublicValue` field.

# MODP Group 2 {#sec-modp-deprec}

Implementations conforming to this specification MUST NOT use
Diffie-Hellman MODP group 2 (the Second Oakley Group, 1024-bit prime).

The requirements from {{RFC4556}} Section 3.2.3.1 are updated as
follows:

* Implementations MUST support MODP group 14 (2048-bit prime,
  {{RFC3526}} Section 3).

* Implementations SHOULD support MODP group 16 (4096-bit prime,
  {{RFC3526}} Section 5).

* Implementations MAY support additional MODP groups defined in
  {{RFC3526}} with a modulus size of 2048 bits or larger.

When a client sends a `clientPublicValue` using a deprecated group,
a KDC conforming to this specification MUST reject the request and
SHOULD reply with `TD-DH-PARAMETERS` containing only groups that
meet the minimum strength requirements defined above.

# SHA-1-Based `octetstring2key()` KDF {#sec-kdf-deprec}

The `supportedKDFs` field defined in {{RFC8636}} is now REQUIRED.

Clients conforming to this specification:

* MUST include the `supportedKDFs` field in the `AuthPack` structure.

* MUST include `id-pkinit-kdf-ah-sha256` in the `supportedKDFs` set.

* SHOULD include `id-pkinit-kdf-ah-sha384` and
  `id-pkinit-kdf-ah-sha512` in the `supportedKDFs` set.

* MUST NOT include `id-pkinit-kdf-ah-sha1` in the `supportedKDFs` set.

KDCs conforming to this specification:

* MUST select a KDF from the `supportedKDFs` field in the request.

* MUST NOT select `id-pkinit-kdf-ah-sha1`.

* If the `supportedKDFs` field is absent from the request, the KDC
  SHOULD reject the request and reply with `KDC_ERR_NO_ACCEPTABLE_KDF`
  (error code 100, {{RFC8636}}).  Alternatively, the KDC MAY fall back
  to the {{RFC4556}} `octetstring2key()` KDF if local policy permits
  interoperability with legacy clients.

# CMS Signature Algorithms {#sec-sig-deprec}

Implementations conforming to this specification MUST NOT use
`sha1WithRSAEncryption` for generating CMS signatures in PKINIT
messages.

For RSA signatures, the following requirements apply:

* Implementations MUST support `sha256WithRSAEncryption` {{RFC5754}}.

* Implementations SHOULD support `sha384WithRSAEncryption` and
  `sha512WithRSAEncryption` {{RFC5754}}.

For ECDSA signatures, the requirements from {{RFC5349}} Section 3 are
updated as follows:

* Implementations MUST support `ecdsa-with-SHA256`.

* Implementations SHOULD support `ecdsa-with-SHA384` and
  `ecdsa-with-SHA512`.

* Implementations SHOULD NOT use `ecdsa-with-SHA1`.  The SHOULD
  requirement for `ecdsa-with-SHA1` in {{RFC5349}} is downgraded.

For CMS digest algorithms, the corresponding requirements apply:

* Implementations MUST support `id-sha256`.

* Implementations SHOULD support `id-sha384` and `id-sha512`.

* Implementations MUST NOT use `id-sha1` for generating CMS signatures
  in PKINIT messages.

When a KDC receives a CMS `SignedData` from a client that uses
`sha1WithRSAEncryption`, `ecdsa-with-SHA1`, or `id-sha1` as the
digest algorithm, the KDC SHOULD reject the request.  A KDC MAY
accept SHA-1-based signatures from legacy clients if local policy
permits, but this is NOT RECOMMENDED.

# `paChecksum2` Extension {#sec-pachecksum2}

This specification defines a new `PAChecksum2` type and extends the
`PKAuthenticator` structure from {{RFC4556}} with a `paChecksum2`
field at tag \[5\].

~~~ asn1
PAChecksum2 ::= SEQUENCE {
    checksum                [0] OCTET STRING,
        -- Checksum computed over KDC-REQ-BODY using the algorithm
        -- specified in algorithmIdentifier.
    algorithmIdentifier     [1] AlgorithmIdentifier
        -- Digest algorithm OID.
}
~~~

The `checksum` field contains the digest computed over KDC-REQ-BODY
using the algorithm identified by `algorithmIdentifier`.  The
`parameters` field of the `AlgorithmIdentifier` MUST be absent.

The `PKAuthenticator` structure from {{RFC4556}} is extended as follows:

~~~ asn1
PKAuthenticator ::= SEQUENCE {
    cusec                   [0] INTEGER (0..999999),
    ctime                   [1] KerberosTime,
    nonce                   [2] INTEGER (0..4294967295),
    paChecksum              [3] OCTET STRING OPTIONAL,
        -- RFC 4556: SHA-1 checksum over KDC-REQ-BODY.
    freshnessToken          [4] OCTET STRING OPTIONAL,
        -- RFC 8070: PA_AS_FRESHNESS token from KDC.
    paChecksum2             [5] PAChecksum2 OPTIONAL,
        -- This specification: algorithm-agile checksum
        -- over KDC-REQ-BODY.
    ...
}
~~~

The following digest algorithms are defined for use with `paChecksum2`:

* Implementations MUST support SHA-256
  (OID 2.16.840.1.101.3.4.2.1, {{RFC5754}}).

* Implementations MAY support SHA-384
  (OID 2.16.840.1.101.3.4.2.2, {{RFC5754}}) and SHA-512
  (OID 2.16.840.1.101.3.4.2.3, {{RFC5754}}).

Client behavior:
: A client constructing a PKINIT request conforming to this
  specification MUST include the `paChecksum2` field and SHOULD include
  the `paChecksum` field (SHA-1, per {{RFC4556}}).  Both checksums,
  when present, are computed over the same KDC-REQ-BODY input.

KDC validation:
: A KDC conforming to this specification MUST require `paChecksum2` to
  be present in the request.  If `paChecksum2` is absent, the KDC
  returns `KDC_ERR_PA_CHECKSUM_MUST_BE_INCLUDED` (error code 79,
  {{RFC4556}}).

  The KDC MUST validate `paChecksum2`.  If `paChecksum` is also
  present, the KDC MUST validate it as well.  The KDC returns the
  following errors:

  * `KDC_ERR_SUMTYPE_NOSUPP` (error code 15, {{RFC4120}}): if the
    digest algorithm in `paChecksum2.algorithmIdentifier` is not
    supported by the KDC.

  * `KRB_AP_ERR_MODIFIED` (error code 41, {{RFC4120}}): if
    verification of `paChecksum2` fails, or if `paChecksum` is
    present and its verification fails.

# IANA Considerations {#sec-iana}

This document has no IANA actions.

# Security Considerations {#sec-security}

KDCs and clients MAY accept legacy algorithm choices from peers that
have not been updated to conform to this specification, subject to
local policy.  Implementations SHOULD log such fallback events.
Deployments are encouraged to coordinate a phased rollout in which the
KDC accepts (but does not yet require) the new fields before
enforcement is enabled.

--- back

# Acknowledgements
{: numbered="false"}

The `paChecksum2` extension is based on the `PAChecksum2` structure
first defined in Microsoft's {{MS-PKCA}} specification.
