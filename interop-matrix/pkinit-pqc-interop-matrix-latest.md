# PKINIT Behavioral Matrix

This document demonstrates the different outcomes to expect when a
Kerberos PKINIT client and KDC interoperate, depending on which
specifications each side implements:

- RFC 4556 (PKINIT base — DH key establishment)
- RFC 5349 (ECDH support)
- RFC 8636 (algorithm agility — KDF negotiation)
- `draft-bokovoy-kitten-pkinit-pqc-01` (ML-KEM key establishment)

## Client Profiles

| ID | RFCs | ML-DSA support | Certificate | KE algo attempted | supportedKDFs sent |
|:---|:---|:---|:---|:---|:---|
| **C1** | 4556 | No | RSA | DH group 14 | (absent) |
| **C2** | 4556+5349 | No | ECDSA | ECDH P-256 | (absent) |
| **C3** | 4556+5349+8636 | No | ECDSA | ECDH P-256 | {id-pkinit-kdf-ah-sha256} |
| **C4** | 4556+5349+8636 | Yes | ML-DSA | ECDH P-256 | {id-pkinit-kdf-ah-sha256} |
| **C5a** | +Draft | Yes | ECDSA (trad) | ML-KEM-768 | {id-alg-hkdf-with-sha512} |
| **C5b** | +Draft | Yes | ML-DSA (PQ) | ML-KEM-768 | {id-alg-hkdf-with-sha512} |

- **C3 vs C4**: same RFCs implemented, but C4 adds ML-DSA support (can
  sign with ML-DSA, can verify ML-DSA). C4 represents a deployment that
  upgraded its crypto library and certificates to ML-DSA before adopting
  the KEM draft. The KE method remains ECDH.
- **C5a/C5b**: implement the KEM draft. First attempt is ML-KEM. They
  differ by certificate type, which determines downgrade behavior on
  err 65 (see Note 4) and KDC signing algorithm enforcement (see
  Note 6). Both can verify ML-DSA.

## KDC Profiles

| ID | RFCs | ML-DSA support | Certificate | KE algos accepted | KDFs accepted | Proactive adv? |
|:---|:---|:---|:---|:---|:---|:---|
| **K1** | 4556 | No | RSA | DH only | octetstring2key (SHA-1 only) | No |
| **K2** | 4556+5349 | No | ECDSA | DH + ECDH | octetstring2key (SHA-1 only) | No |
| **K3** | 4556+5349+8636 | No | ECDSA | DH + ECDH | SHA-1 + SHA-256 (negotiable) | No |
| **K4** | 4556+5349+8636 | Yes | ML-DSA | DH + ECDH | SHA-1 + SHA-256 (negotiable) | No |
| **K5a** | +Draft | Yes | ECDSA (trad) | DH + ECDH + ML-KEM | SHA-256 (DH) + HKDF-SHA-512 (KEM) | Yes (SHOULD) |
| **K5b** | +Draft | Yes | ML-DSA (PQ) | DH + ECDH + ML-KEM | SHA-256 (DH) + HKDF-SHA-512 (KEM) | Yes (SHOULD) |

- **K3 vs K4**: same RFCs implemented, but K4 adds ML-DSA support (can
  verify ML-DSA client signatures, uses ML-DSA certificate). K4
  represents a KDC that upgraded to ML-DSA on the DH/ECDH path before
  adopting the KEM draft.
- **K5a vs K5b**: differ by KDC certificate type (traditional vs PQ).
  This determines whether the KDC reply provides PQC authentication.

---

## Interoperability Matrix

Each cell describes the observable outcome of a PKINIT AS exchange.
Annotations *(Nx)* refer to notes at the bottom.

<table>
<thead>
<tr>
  <th></th>
  <th>K1<br/><small>4556, RSA cert, DH only</small></th>
  <th>K2<br/><small>+5349, ECDSA cert, +ECDH</small></th>
  <th>K3<br/><small>+8636, ECDSA cert, +KDF</small></th>
  <th>K4<br/><small>+8636, ML-DSA cert+verif</small></th>
  <th>K5a<br/><small>+Draft, ECDSA cert, +KEM</small></th>
  <th>K5b<br/><small>+Draft, ML-DSA cert, +KEM</small></th>
</tr>
</thead>
<tbody>

<tr>
<td><b>C1</b><br/><small>4556, RSA cert, DH grp 14</small></td>
<td>

**OK** ✓
DH grp 14.
KDF: octetstring2key (SHA-1).
KDC signs with RSA.

</td>
<td>

**OK** ✓
DH grp 14.
KDF: octetstring2key (SHA-1).
KDC signs with ECDSA.

</td>
<td>

**OK** ✓
DH grp 14.
No supportedKDFs → KDC omits kdf.
KDF: octetstring2key (SHA-1).
KDC signs with ECDSA.

</td>
<td>

**FAIL** ✗ *(N1)*
KDC signs with ML-DSA.
Client cannot verify ML-DSA.

</td>
<td>

**OK** ✓
DH grp 14.
No supportedKDFs → octetstring2key (SHA-1).
KDC signs with ECDSA.

</td>
<td>

**FAIL** ✗ *(N1)*
KDC signs with ML-DSA.
Client cannot verify ML-DSA.

</td>
</tr>

<tr>
<td><b>C2</b><br/><small>+5349, ECDSA cert, ECDH P-256</small></td>
<td>

**err 65** → **fallback OK** *(N3)*
KDC rejects ECDH → err 65 + TD-DH-PARAMETERS.
Retry with DH → succeeds.
KDF: octetstring2key (SHA-1).

</td>
<td>

**OK** ✓
ECDH P-256.
KDF: octetstring2key (SHA-1).
KDC signs with ECDSA.

</td>
<td>

**OK** ✓
ECDH P-256.
No supportedKDFs → octetstring2key (SHA-1).
KDC signs with ECDSA.

</td>
<td>

**FAIL** ✗ *(N1)*
KDC signs with ML-DSA.
Client cannot verify ML-DSA.

</td>
<td>

**OK** ✓
ECDH P-256.
No supportedKDFs → octetstring2key (SHA-1).
KDC signs with ECDSA.

</td>
<td>

**FAIL** ✗ *(N1)*
KDC signs with ML-DSA.
Client cannot verify ML-DSA.

</td>
</tr>

<tr>
<td><b>C3</b><br/><small>+8636, ECDSA cert, ECDH, KDF nego</small></td>
<td>

**err 65** → **fallback OK** *(N3)*
KDC rejects ECDH → err 65 + TD-DH-PARAMETERS.
Retry with DH → succeeds.
KDC ignores supportedKDFs.
KDF: octetstring2key (SHA-1); no kdf in reply → local policy. *(N5)*

</td>
<td>

**OK** ✓
ECDH P-256.
KDC ignores supportedKDFs.
KDF: octetstring2key (SHA-1).
No kdf in reply → local policy. *(N5)*

</td>
<td>

**OK** ✓
ECDH P-256.
KDC picks id-pkinit-kdf-ah-sha256.
KDF: SP 800-56A SHA-256.
KDC signs with ECDSA.

</td>
<td>

**FAIL** ✗ *(N1)*
KDC signs with ML-DSA.
Client cannot verify ML-DSA.

</td>
<td>

**OK** ✓
ECDH P-256.
KDC picks id-pkinit-kdf-ah-sha256.
KDF: SP 800-56A SHA-256.
KDC signs with ECDSA.

</td>
<td>

**FAIL** ✗ *(N1)*
KDC signs with ML-DSA.
Client cannot verify ML-DSA.

</td>
</tr>

<tr>
<td><b>C4</b><br/><small>+8636, ML-DSA cert+verif, ECDH, KDF nego</small></td>
<td>

**FAIL** ✗ *(N2)*
KDC cannot verify ML-DSA sig on AuthPack.
→ err 64 or err 80.

</td>
<td>

**FAIL** ✗ *(N2)*
KDC cannot verify ML-DSA sig on AuthPack.
→ err 64 or err 80.

</td>
<td>

**FAIL** ✗ *(N2)*
KDC cannot verify ML-DSA sig on AuthPack.
→ err 64 or err 80.

</td>
<td>

**OK** ✓
ECDH P-256.
KDC picks id-pkinit-kdf-ah-sha256.
KDF: SP 800-56A SHA-256.
Both sign with ML-DSA.
**PQ auth (both sides), traditional KE.**

</td>
<td>

**OK** ✓
ECDH P-256.
KDC picks id-pkinit-kdf-ah-sha256.
KDF: SP 800-56A SHA-256.
Client signs ML-DSA; KDC signs ECDSA.
**PQ client auth, traditional KDC auth + KE.**

</td>
<td>

**OK** ✓
ECDH P-256.
KDC picks id-pkinit-kdf-ah-sha256.
KDF: SP 800-56A SHA-256.
Both sign with ML-DSA.
**PQ auth (both sides), traditional KE.**

</td>
</tr>

<tr>
<td><b>C5a</b><br/><small>+Draft, ECDSA cert, ML-KEM-768</small></td>
<td>

**err 65** → **fallback OK** *(N4)*
KDC rejects ML-KEM → err 65 + TD-DH-PARAMETERS.
Trad cert → client MAY fall back to DH.
Retry with DH → succeeds.
KDF: octetstring2key (SHA-1).

</td>
<td>

**err 65** → **fallback OK** *(N4)*
KDC rejects ML-KEM → err 65 + TD-DH-PARAMETERS.
Trad cert → client MAY fall back to ECDH.
Retry → ECDH P-256 succeeds.
KDF: octetstring2key (SHA-1).

</td>
<td>

**err 65** → **fallback OK** *(N4)*
KDC rejects ML-KEM → err 65.
Trad cert → client MAY fall back to ECDH.
Retry → ECDH + KDF negotiation.
KDF: SP 800-56A SHA-256.

</td>
<td>

**err 65** → **fallback OK** *(N4)*
KDC rejects ML-KEM → err 65.
Trad cert → client MAY fall back to ECDH.
Retry → ECDH + KDF negotiation.
KDC signs with ML-DSA; C5a verifies.

</td>
<td>

**OK** ✓
ML-KEM-768.
KDF: HKDF-SHA-512 (authenticated in KDCKEMInfo).
Client signs ECDSA; KDC signs ECDSA.
**PQ key establishment, traditional auth.**

</td>
<td>

**OK** ✓
ML-KEM-768.
KDF: HKDF-SHA-512 (authenticated in KDCKEMInfo).
Client signs ECDSA; KDC signs ML-DSA.
**PQ key establishment + PQ KDC auth.**

</td>
</tr>

<tr>
<td><b>C5b</b><br/><small>+Draft, ML-DSA cert, ML-KEM-768</small></td>
<td>

**FAIL** ✗ *(N4)*
KDC rejects ML-KEM → err 65.
PQ cert → downgrade forbidden.
Exchange fails.

</td>
<td>

**FAIL** ✗ *(N4)*
KDC rejects ML-KEM → err 65.
PQ cert → downgrade forbidden.
Exchange fails.

</td>
<td>

**FAIL** ✗ *(N4)*
KDC rejects ML-KEM → err 65.
PQ cert → downgrade forbidden.
Exchange fails.

</td>
<td>

**FAIL** ✗ *(N4)*
KDC rejects ML-KEM → err 65.
PQ cert → downgrade forbidden.
Exchange fails.

</td>
<td>

**FAIL** ✗ *(N6)*
ML-KEM-768 succeeds.
KDC signs with ECDSA.
PQ cert → client requires PQ KDC signature.
Client rejects traditional KDC signature.

</td>
<td>

**OK** ✓ — **Full PQ**
ML-KEM-768.
KDF: HKDF-SHA-512 (authenticated in KDCKEMInfo).
Client signs ML-DSA; KDC signs ML-DSA.
**Full post-quantum on both sides.**

</td>
</tr>

</tbody>
</table>

---

## Notes

### Note 1: ML-DSA KDC Signature vs. Client Capabilities

When a KDC uses ML-DSA to sign its reply, clients that don't support
ML-DSA verification (C1, C2, C3) cannot authenticate → exchange fails
even though the KE mechanism itself would work.

A **K4 or K5b KDC (ML-DSA cert) is incompatible with clients that lack
ML-DSA verification support.** Mixed deployments need K3/K5a (traditional
KDC cert) or dual KDC certificates.

### Note 2: ML-DSA Client Signature vs. KDC Capabilities

A C4/C5b client signs AuthPack with ML-DSA. A KDC that doesn't support
ML-DSA verification (K1, K2, K3) cannot verify this signature:
- err 64 (`KDC_ERR_INVALID_SIG`) if verification is attempted and fails.
- err 80 (`KDC_ERR_DIGEST_IN_SIGNED_DATA_NOT_ACCEPTED`) if the
  signature algorithm is rejected upfront.

An ML-DSA client certificate is only usable against KDCs that support
ML-DSA verification (K4, K5a, K5b).

### Note 3: ECDH Against DH-Only KDC (K1)

K1 may not recognize the ECDH OID (id-ecPublicKey) in
clientPublicValue. In that case K1 returns err 65 with
TD-DH-PARAMETERS listing its DH groups. The client can retry with a DH
group from that list.

RFC 5349 is Informational and does not change RFC 4556 wire formats, so
some K1 implementations may support ECDH without formally implementing
RFC 5349. The matrix assumes K1 does not.

### Note 4: KE Downgrade Rules After err 65

The draft §9:
- **PQ cert + KEM rejected → MUST NOT fall back** to DH/ECDH. MAY retry
  with a different PQ KEM.
- **Traditional cert + KEM rejected → MAY fall back** to DH/ECDH.

This is why C5a and C5b differ against non-KEM KDCs:
- **C5a** (ECDSA cert): fallback allowed → succeeds against K1/K2/K3/K4
  via DH or ECDH.
- **C5b** (ML-DSA cert): fallback forbidden → fails against all
  non-KEM KDCs.

C5b **cannot authenticate against any KDC that doesn't support ML-KEM.**
This is by design — using a PQ certificate signals commitment to PQ-only
operation. Even if the downgrade rule were hypothetically relaxed,
pre-ML-DSA KDCs (K1/K2/K3) would still reject the ML-DSA signature on
AuthPack.

### Note 5: KDF Negotiation with Pre-8636 KDC

When a C3+ client sends supportedKDFs but the KDC (K1/K2) doesn't
implement RFC 8636, the KDC ignores the unknown extension and omits the
kdf field in the reply. The client detects the missing kdf and must
decide per local policy:

- **Accept**: use octetstring2key (SHA-1), compatible but weaker.
- **Reject**: refuse the reply, authentication fails.

RFC 8636 §7 says: *"The client MUST use the [RFC4556] KDF or reject the
reply if local policy forbids the use of the old KDF."*

### Note 6: KDC Signing Algorithm Enforcement (PQ Client Certificate)

The draft §9: when a client uses a PQ signing certificate and sends a PQ
KEM encapsulation key, the client **MUST verify that the KDC signed its
reply using a quantum-resistant algorithm**. If the KDC signed with a
traditional algorithm, the client MUST reject the response.

This affects **C5b × K5a**: ML-KEM key establishment succeeds, but K5a
signs with ECDSA. C5b detects the traditional KDC signature and aborts.
Without this rule, the exchange would complete with PQ client
authentication and PQ key establishment, but traditional KDC
authentication — leaving the KDC side vulnerable to impersonation by a
quantum-capable adversary.

C5b therefore requires a **full PQ KDC** (K5b) to complete the exchange.
