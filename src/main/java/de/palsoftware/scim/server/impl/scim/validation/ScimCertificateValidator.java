package de.palsoftware.scim.server.impl.scim.validation;

import de.palsoftware.scim.server.impl.scim.error.ScimException;

import java.io.ByteArrayInputStream;
import java.security.cert.Certificate;
import java.security.cert.CertificateException;
import java.security.cert.CertificateFactory;
import java.util.Arrays;
import java.util.Base64;
import java.util.Collection;

/**
 * Validates SCIM x509Certificates.value (RFC 7643 §2.3.6 & §4.1.2):
 * - Must be valid Base64-encoded binary data (padded or unpadded, no PEM headers).
 * - Each value MUST contain exactly one DER-encoded X.509 certificate when X.509 DER
 *   structures are supplied; concatenated or bundled multiple X.509 certificates are rejected
 *   with HTTP 400 invalidValue, while single certificates and opaque binary test blobs succeed.
 */
public final class ScimCertificateValidator {

    private ScimCertificateValidator() {
    }

    public static String validateSingleDerCertificateOrBinary(String value) {
        validateSingleDerCertificateOrBinary(value, "x509Certificates.value");
        return value.trim();
    }

    public static String validateAndCanonicalizeBase64(String value, String fieldName) {
        validateSingleDerCertificateOrBinary(value, fieldName);
        byte[] decoded = decodeBase64(value.trim(), fieldName);
        return Base64.getEncoder().encodeToString(decoded);
    }

    public static void validateSingleDerCertificateOrBinary(String value, String fieldName) {
        if (value == null || value.isBlank()) {
            throw new ScimException(400, "invalidValue", fieldName + " must not be blank");
        }
        String trimmed = value.trim();
        if (trimmed.contains("-----BEGIN")) {
            throw new ScimException(400, "invalidValue",
                    fieldName + " must be raw DER Base64, not PEM-armored");
        }

        byte[] decoded = decodeBase64(trimmed, fieldName);
        if (decoded.length == 0) {
            throw new ScimException(400, "invalidValue", fieldName + " must not be empty");
        }

        rejectMultipleDerCertificates(decoded, fieldName);
    }

    private static byte[] decodeBase64(String trimmed, String fieldName) {
        // Strip whitespace/newlines only if valid MIME/standard Base64? No: RFC 7643 §2.3.6 requires Base64 without spaces
        int mod = trimmed.length() % 4;
        if (mod == 1) {
            throw new ScimException(400, "invalidValue", fieldName + " must be base64-encoded");
        }
        String padded = switch (mod) {
            case 2 -> trimmed + "==";
            case 3 -> trimmed + "=";
            default -> trimmed;
        };
        try {
            return Base64.getDecoder().decode(padded);
        } catch (IllegalArgumentException e) {
            throw new ScimException(400, "invalidValue", fieldName + " must be base64-encoded", e);
        }
    }

    private static void rejectMultipleDerCertificates(byte[] decoded, String fieldName) {
        // First check standard X.509 CertificateFactory stream collection (catches concatenated DER certs and PKCS#7 chains)
        try {
            CertificateFactory cf = CertificateFactory.getInstance("X.509");
            Collection<? extends Certificate> certs = cf.generateCertificates(new ByteArrayInputStream(decoded));
            if (certs != null && certs.size() > 1) {
                throw new ScimException(400, "invalidValue",
                        fieldName + " MUST NOT contain multiple certificates");
            }
        } catch (ScimException se) {
            throw se;
        } catch (CertificateException ignored) {
            // May be an opaque non-X.509 binary test value (RFC 7643 §2.3.6) or custom ASN.1 wrapper; inspect TLV below
        }

        // Inspect ASN.1 DER SEQUENCE boundaries directly
        if (decoded.length >= 4 && (decoded[0] & 0xFF) == 0x30) {
            DerElement first = readDerElement(decoded, 0);
            if (first != null) {
                if (first.totalLength < decoded.length) {
                    // Trailing bytes after the first DER SEQUENCE: if the first element is a valid X.509 certificate,
                    // then additional data / concatenated certificate(s) were appended!
                    byte[] firstSlice = Arrays.copyOfRange(decoded, 0, first.totalLength);
                    if (isValidX509Certificate(firstSlice)) {
                        throw new ScimException(400, "invalidValue",
                                fieldName + " MUST NOT contain multiple certificates");
                    }
                } else if (first.totalLength == decoded.length && !isDerX509CertificateStructure(decoded)) {
                    // Check if outer SEQUENCE is a SEQUENCE OF Certificate containing >= 2 X.509 certificates
                    int certChildren = 0;
                    int pos = first.contentOffset;
                    while (pos < decoded.length) {
                        DerElement child = readDerElement(decoded, pos);
                        if (child == null || child.totalLength <= 0 || pos + child.totalLength > decoded.length) {
                            break;
                        }
                        if ((decoded[pos] & 0xFF) == 0x30) {
                            byte[] childBytes = Arrays.copyOfRange(decoded, pos, pos + child.totalLength);
                            if (isValidX509Certificate(childBytes)) {
                                certChildren++;
                                if (certChildren > 1) {
                                    throw new ScimException(400, "invalidValue",
                                            fieldName + " MUST NOT contain multiple certificates");
                                }
                            }
                        }
                        pos += child.totalLength;
                    }
                }
            }
        }
    }

    private static boolean isValidX509Certificate(byte[] derBytes) {
        if (isDerX509CertificateStructure(derBytes)) {
            return true;
        }
        try {
            CertificateFactory cf = CertificateFactory.getInstance("X.509");
            Certificate cert = cf.generateCertificate(new ByteArrayInputStream(derBytes));
            return cert != null;
        } catch (CertificateException e) {
            return false;
        }
    }

    /**
     * Recognizes an RFC 5280 §4.1 ASN.1 DER X.509 {@code Certificate} structure even when JDK
     * {@link CertificateFactory} rejects legacy/explicit-EC {@code SubjectPublicKeyInfo} parameters:
     * <pre>
     * Certificate ::= SEQUENCE {
     *     tbsCertificate       TBSCertificate,      -- SEQUENCE starting with [0] EXPLICIT Version (0xA0) or INTEGER serialNumber (0x02)
     *     signatureAlgorithm   AlgorithmIdentifier, -- SEQUENCE starting with OBJECT IDENTIFIER (0x06)
     *     signatureValue       BIT STRING           -- tag 0x03 with unused-bits octet 0..7
     * }
     * </pre>
     */
    static boolean isDerX509CertificateStructure(byte[] derBytes) {
        if (derBytes == null || derBytes.length < 16 || (derBytes[0] & 0xFF) != 0x30) {
            return false;
        }
        DerElement outer = readDerElement(derBytes, 0);
        if (outer == null || outer.totalLength != derBytes.length) {
            return false;
        }
        int pos = outer.contentOffset;
        int end = outer.totalLength;

        // 1. tbsCertificate: SEQUENCE starting with 0xA0 ([0] EXPLICIT Version) or 0x02 (INTEGER serialNumber)
        if (pos >= end || (derBytes[pos] & 0xFF) != 0x30) {
            return false;
        }
        DerElement tbs = readDerElement(derBytes, pos);
        if (tbs == null || tbs.contentLength < 4 || pos + tbs.totalLength >= end) {
            return false;
        }
        int tbsFirstTag = derBytes[tbs.contentOffset] & 0xFF;
        if (tbsFirstTag != 0xA0 && tbsFirstTag != 0x02) {
            return false;
        }
        DerElement tbsFirst = readDerElement(derBytes, tbs.contentOffset);
        if (tbsFirst == null || tbs.contentOffset + tbsFirst.totalLength > pos + tbs.totalLength) {
            return false;
        }
        pos += tbs.totalLength;

        // 2. signatureAlgorithm: SEQUENCE starting with OBJECT IDENTIFIER (0x06)
        if (pos >= end || (derBytes[pos] & 0xFF) != 0x30) {
            return false;
        }
        DerElement sigAlg = readDerElement(derBytes, pos);
        if (sigAlg == null || sigAlg.contentLength < 2 || pos + sigAlg.totalLength >= end) {
            return false;
        }
        if ((derBytes[sigAlg.contentOffset] & 0xFF) != 0x06) {
            return false;
        }
        DerElement oid = readDerElement(derBytes, sigAlg.contentOffset);
        if (oid == null || oid.contentLength < 1 || sigAlg.contentOffset + oid.totalLength > pos + sigAlg.totalLength) {
            return false;
        }
        pos += sigAlg.totalLength;

        // 3. signatureValue: BIT STRING (0x03) with valid unused-bits count (0..7), consuming exact end of outer SEQUENCE
        if (pos >= end || (derBytes[pos] & 0xFF) != 0x03) {
            return false;
        }
        DerElement sigVal = readDerElement(derBytes, pos);
        if (sigVal == null || sigVal.contentLength < 1) {
            return false;
        }
        int unusedBits = derBytes[sigVal.contentOffset] & 0xFF;
        if (unusedBits > 7) {
            return false;
        }
        pos += sigVal.totalLength;

        return pos == end;
    }

    private record DerElement(int contentOffset, int contentLength, int totalLength) {
    }

    private static DerElement readDerElement(byte[] buf, int offset) {
        if (offset < 0 || offset + 2 > buf.length) {
            return null;
        }
        int lenByte = buf[offset + 1] & 0xFF;
        if ((lenByte & 0x80) == 0) {
            int contentLen = lenByte;
            int total = 2 + contentLen;
            return ((long) offset + total <= buf.length) ? new DerElement(offset + 2, contentLen, total) : null;
        }
        int numLenBytes = lenByte & 0x7F;
        if (numLenBytes == 0 || numLenBytes > 4 || offset + 2 + numLenBytes > buf.length) {
            return null;
        }
        long contentLenLong = 0;
        for (int i = 0; i < numLenBytes; i++) {
            contentLenLong = (contentLenLong << 8) | (buf[offset + 2 + i] & 0xFF);
        }
        if (contentLenLong < 0 || contentLenLong > buf.length) {
            return null;
        }
        int contentLen = (int) contentLenLong;
        int headerLen = 2 + numLenBytes;
        int total = headerLen + contentLen;
        return ((long) offset + total <= buf.length) ? new DerElement(offset + headerLen, contentLen, total) : null;
    }
}
