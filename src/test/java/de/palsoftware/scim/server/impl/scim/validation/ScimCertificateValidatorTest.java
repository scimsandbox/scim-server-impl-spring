package de.palsoftware.scim.server.impl.scim.validation;

import de.palsoftware.scim.server.impl.scim.error.ScimException;
import org.junit.jupiter.api.Test;

import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.math.BigInteger;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.cert.CertificateException;
import java.security.cert.CertificateFactory;
import java.util.Base64;
import java.util.Random;

import static org.junit.jupiter.api.Assertions.*;

class ScimCertificateValidatorTest {

    // Minimal valid self-contained DER X.509v1 certificate bytes constructed via ASN.1 DER
    private static byte[] buildMinimalDerX509Cert(int serial) throws Exception {
        KeyPairGenerator kpg = KeyPairGenerator.getInstance("RSA");
        kpg.initialize(2048);
        KeyPair kp = kpg.generateKeyPair();
        byte[] spki = kp.getPublic().getEncoded(); // SubjectPublicKeyInfo DER SEQUENCE

        // AlgorithmIdentifier: sha256WithRSAEncryption (1.2.840.113549.1.1.11) + NULL
        byte[] algId = new byte[] {
                0x30, 0x0d,
                0x06, 0x09, 0x2a, (byte) 0x86, 0x48, (byte) 0x86, (byte) 0xf7, 0x0d, 0x01, 0x01, 0x0b,
                0x05, 0x00
        };
        // Name: CN=Test (SEQUENCE -> SET -> SEQUENCE -> OID 2.5.4.3 + UTF8String "Test")
        byte[] name = new byte[] {
                0x30, 0x0f,
                0x31, 0x0d,
                0x30, 0x0b,
                0x06, 0x03, 0x55, 0x04, 0x03,
                0x0c, 0x04, 'T', 'e', 's', 't'
        };
        // Validity: GeneralizedTime 20250101000000Z .. 20350101000000Z
        byte[] notBefore = derTag(0x18, "20250101000000Z".getBytes());
        byte[] notAfter = derTag(0x18, "20350101000000Z".getBytes());
        byte[] validity = derTag(0x30, concat(notBefore, notAfter));

        byte[] serialDer = derTag(0x02, BigInteger.valueOf(serial).toByteArray());
        byte[] tbs = derTag(0x30, concat(serialDer, algId, name, validity, name, spki));

        java.security.Signature sig = java.security.Signature.getInstance("SHA256withRSA");
        sig.initSign(kp.getPrivate());
        sig.update(tbs);
        byte[] sigBytes = sig.sign();
        byte[] bitStringBody = new byte[sigBytes.length + 1];
        System.arraycopy(sigBytes, 0, bitStringBody, 1, sigBytes.length);
        byte[] sigBitString = derTag(0x03, bitStringBody);

        return derTag(0x30, concat(tbs, algId, sigBitString));
    }

    private static byte[] derTag(int tag, byte[] content) {
        ByteArrayOutputStream out = new ByteArrayOutputStream();
        out.write(tag);
        int len = content.length;
        if (len < 128) {
            out.write(len);
        } else if (len < 256) {
            out.write(0x81);
            out.write(len);
        } else {
            out.write(0x82);
            out.write((len >> 8) & 0xFF);
            out.write(len & 0xFF);
        }
        out.writeBytes(content);
        return out.toByteArray();
    }

    private static byte[] concat(byte[]... parts) {
        ByteArrayOutputStream out = new ByteArrayOutputStream();
        for (byte[] p : parts) {
            out.writeBytes(p);
        }
        return out.toByteArray();
    }

    @Test
    void testAllowsSingleDerX509Certificate() throws Exception {
        byte[] cert1 = buildMinimalDerX509Cert(1);
        String b64 = Base64.getEncoder().encodeToString(cert1);
        assertEquals(b64, ScimCertificateValidator.validateSingleDerCertificateOrBinary(b64));
    }

    @Test
    void testRejectsTwoConcatenatedDerCertificates() throws Exception {
        byte[] cert1 = buildMinimalDerX509Cert(1);
        byte[] cert2 = buildMinimalDerX509Cert(2);
        String b64 = Base64.getEncoder().encodeToString(concat(cert1, cert2));

        ScimException ex = assertThrows(ScimException.class,
                () -> ScimCertificateValidator.validateSingleDerCertificateOrBinary(b64));
        assertEquals(400, ex.getHttpStatus());
        assertEquals("invalidValue", ex.getScimType());
    }

    @Test
    void testRejectsSequenceOfTwoDerCertificates() throws Exception {
        byte[] cert1 = buildMinimalDerX509Cert(10);
        byte[] cert2 = buildMinimalDerX509Cert(20);
        byte[] seqOfCerts = derTag(0x30, concat(cert1, cert2));
        String b64 = Base64.getEncoder().encodeToString(seqOfCerts);

        ScimException ex = assertThrows(ScimException.class,
                () -> ScimCertificateValidator.validateSingleDerCertificateOrBinary(b64));
        assertEquals(400, ex.getHttpStatus());
        assertEquals("invalidValue", ex.getScimType());
    }

    @Test
    void testAllowsArbitraryOpaqueBinaryBase64AndUnpaddedBase64() {
        byte[] random33 = new byte[33];
        new Random(42).nextBytes(random33);
        String b64 = Base64.getEncoder().encodeToString(random33);
        assertEquals(b64, ScimCertificateValidator.validateSingleDerCertificateOrBinary(b64));

        // Unpadded Base64 ("AB" -> "QUI")
        assertEquals("QUI", ScimCertificateValidator.validateSingleDerCertificateOrBinary("QUI"));
    }

    @Test
    void testRejectsPemArmorAndMalformedBase64() {
        assertThrows(ScimException.class,
                () -> ScimCertificateValidator.validateSingleDerCertificateOrBinary("-----BEGIN CERTIFICATE-----\ndGVzdA==\n-----END CERTIFICATE-----"));
        assertThrows(ScimException.class,
                () -> ScimCertificateValidator.validateSingleDerCertificateOrBinary("not valid base64!!!"));
    }

    /**
     * Builds a syntactically valid RFC 5280 DER X.509 certificate whose SubjectPublicKeyInfo
     * uses explicit EC curve parameters (SpecifiedECDomain SEQUENCE instead of a named curve OID),
     * which modern JDK CertificateFactory("X.509") rejects with CertificateException.
     */
    private static byte[] buildExplicitEcParamsDerX509Cert(int serial, boolean v3ExplicitVersion) {
        // ecdsa-with-SHA256 (1.2.840.10045.4.3.2)
        byte[] sigAlg = derTag(0x30, new byte[] {
                0x06, 0x08, 0x2a, (byte) 0x86, 0x48, (byte) 0xce, 0x3d, 0x04, 0x03, 0x02
        });
        // SubjectPublicKeyInfo with id-ecPublicKey (1.2.840.10045.2.1) + explicit SpecifiedECDomain SEQUENCE
        byte[] explicitCurveParams = derTag(0x30, concat(
                derTag(0x02, new byte[] { 0x01 }), //ECPVer = 1
                derTag(0x30, new byte[] { 0x06, 0x07, 0x2a, (byte) 0x86, 0x48, (byte) 0xce, 0x3d, 0x01, 0x01, 0x02, 0x01, 0x11 })
        ));
        byte[] spkiAlg = derTag(0x30, concat(
                new byte[] { 0x06, 0x07, 0x2a, (byte) 0x86, 0x48, (byte) 0xce, 0x3d, 0x02, 0x01 },
                explicitCurveParams
        ));
        byte[] spkiKey = derTag(0x03, new byte[] { 0x00, 0x04, 0x01, 0x02, 0x03, 0x04 });
        byte[] spki = derTag(0x30, concat(spkiAlg, spkiKey));

        byte[] name = new byte[] {
                0x30, 0x0f, 0x31, 0x0d, 0x30, 0x0b,
                0x06, 0x03, 0x55, 0x04, 0x03,
                0x0c, 0x04, 'T', 'e', 's', 't'
        };
        byte[] validity = derTag(0x30, concat(
                derTag(0x17, "250101000000Z".getBytes()),
                derTag(0x17, "350101000000Z".getBytes())
        ));
        byte[] serialDer = derTag(0x02, BigInteger.valueOf(serial).toByteArray());
        byte[] tbsContent = v3ExplicitVersion
                ? concat(derTag(0xA0, derTag(0x02, new byte[] { 0x02 })), serialDer, sigAlg, name, validity, name, spki)
                : concat(serialDer, sigAlg, name, validity, name, spki);
        byte[] tbs = derTag(0x30, tbsContent);
        byte[] sigVal = derTag(0x03, new byte[] { 0x00, 0x30, 0x06, 0x02, 0x01, 0x01, 0x02, 0x01, 0x02 });
        return derTag(0x30, concat(tbs, sigAlg, sigVal));
    }

    @Test
    void testHandlesExplicitEcParameterDerCertificatesRejectedByJdkCertificateFactory() throws Exception {
        byte[] v1Cert1 = buildExplicitEcParamsDerX509Cert(1, false);
        byte[] v3Cert2 = buildExplicitEcParamsDerX509Cert(2, true);

        // Confirm JDK CertificateFactory throws CertificateException on explicit EC parameters
        CertificateFactory cf = CertificateFactory.getInstance("X.509");
        assertThrows(CertificateException.class, () -> cf.generateCertificate(new ByteArrayInputStream(v1Cert1)));

        // Single explicit-EC DER certificates (both v1 and v3) MUST be accepted
        String singleV1 = Base64.getEncoder().encodeToString(v1Cert1);
        String singleV3 = Base64.getEncoder().encodeToString(v3Cert2);
        assertEquals(singleV1, ScimCertificateValidator.validateSingleDerCertificateOrBinary(singleV1));
        assertEquals(singleV3, ScimCertificateValidator.validateSingleDerCertificateOrBinary(singleV3));

        // Concatenated explicit-EC DER certificates MUST be rejected with 400 invalidValue
        String concatenated = Base64.getEncoder().encodeToString(concat(v1Cert1, v3Cert2));
        ScimException exConcat = assertThrows(ScimException.class,
                () -> ScimCertificateValidator.validateSingleDerCertificateOrBinary(concatenated));
        assertEquals(400, exConcat.getHttpStatus());
        assertEquals("invalidValue", exConcat.getScimType());

        // SEQUENCE OF explicit-EC DER certificates MUST also be rejected with 400 invalidValue
        String seqOf = Base64.getEncoder().encodeToString(derTag(0x30, concat(v1Cert1, v3Cert2)));
        ScimException exSeq = assertThrows(ScimException.class,
                () -> ScimCertificateValidator.validateSingleDerCertificateOrBinary(seqOf));
        assertEquals(400, exSeq.getHttpStatus());
        assertEquals("invalidValue", exSeq.getScimType());
    }
}
