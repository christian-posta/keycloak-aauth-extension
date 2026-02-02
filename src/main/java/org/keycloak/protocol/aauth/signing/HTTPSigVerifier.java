/*
 * Copyright 2025 Red Hat, Inc. and/or its affiliates
 * and other contributors as indicated by the @author tags.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 * http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

package org.keycloak.protocol.aauth.signing;

import org.jboss.logging.Logger;
import org.keycloak.http.HttpRequest;
import org.keycloak.models.KeycloakSession;
import org.keycloak.protocol.aauth.signing.exceptions.SignatureBaseException;
import org.keycloak.protocol.aauth.signing.exceptions.SignatureKeyParseException;
import org.keycloak.protocol.aauth.signing.exceptions.SignatureVerificationException;
import org.keycloak.protocol.aauth.signing.schemes.SignatureScheme;
import org.keycloak.protocol.aauth.signing.schemes.SignatureSchemeFactory;

import java.security.PublicKey;
import java.util.Base64;
import java.util.List;

/**
 * Main HTTP Message Signature verifier per RFC 9421 and AAuth profile.
 * 
 * Verifies HTTP Message Signatures by:
 * 1. Parsing Signature-Key header to determine scheme
 * 2. Discovering public key based on scheme
 * 3. Building signature base string
 * 4. Verifying signature using discovered key
 * 
 * @see <a href="https://datatracker.ietf.org/doc/html/rfc9421">RFC 9421: HTTP Message Signatures</a>
 */
public class HTTPSigVerifier {

    private static final Logger logger = Logger.getLogger(HTTPSigVerifier.class);

    private final KeycloakSession session;

    public HTTPSigVerifier(KeycloakSession session) {
        this.session = session;
    }

    /**
     * Verify an HTTP Message Signature without body validation.
     * 
     * Note: This method does NOT validate Content-Digest against the body.
     * Use {@link #verify(HttpRequest, byte[])} when body validation is needed.
     * 
     * @param request The HTTP request containing signature headers
     * @return Verification result containing agent identity and public key
     * @throws SignatureVerificationException If verification fails
     */
    public VerificationResult verify(HttpRequest request) throws SignatureVerificationException {
        return verify(request, null);
    }

    /**
     * Verify an HTTP Message Signature with Content-Digest body validation.
     * 
     * Per RFC 9421 Section 7.2.8, when Content-Digest is included in the signature,
     * verifiers MUST validate that the digest matches the actual received content
     * to prevent body substitution attacks.
     * 
     * @param request The HTTP request containing signature headers
     * @param bodyBytes The actual request body bytes (required if content-digest is signed)
     * @return Verification result containing agent identity and public key
     * @throws SignatureVerificationException If verification fails or Content-Digest doesn't match body
     */
    public VerificationResult verify(HttpRequest request, byte[] bodyBytes) throws SignatureVerificationException {
        // 1. Extract and parse Signature-Key header
        String signatureKeyHeader = request.getHttpHeaders().getHeaderString("Signature-Key");
        if (signatureKeyHeader == null) {
            throw new SignatureVerificationException("Missing Signature-Key header");
        }

        SignatureKeyParser keyParser;
        try {
            keyParser = new SignatureKeyParser(signatureKeyHeader);
        } catch (SignatureKeyParseException e) {
            throw new SignatureVerificationException("Failed to parse Signature-Key header", e);
        }

        // 2. Extract Signature-Input header
        String signatureInputHeader = request.getHttpHeaders().getHeaderString("Signature-Input");
        if (signatureInputHeader == null) {
            throw new SignatureVerificationException("Missing Signature-Input header");
        }

        // 3. Extract Signature header
        String signatureHeader = request.getHttpHeaders().getHeaderString("Signature");
        if (signatureHeader == null) {
            throw new SignatureVerificationException("Missing Signature header");
        }

        // 4. Verify label consistency (AAuth profile requirement)
        String signatureLabel = extractSignatureLabel(signatureHeader);
        if (!signatureLabel.equals(keyParser.getSignatureLabel())) {
            throw new SignatureVerificationException(
                "Signature label mismatch: Signature-Key has '" + keyParser.getSignatureLabel() + 
                "' but Signature has '" + signatureLabel + "'");
        }

        // 5. Store body bytes in session for schemes that need to parse form data (e.g., token exchange)
        if (bodyBytes != null) {
            session.setAttribute("aauth.request.body.bytes", bodyBytes);
        }

        // 6. Discover public key based on scheme
        SignatureScheme scheme = SignatureSchemeFactory.create(session, keyParser);
        PublicKey publicKey;
        try {
            publicKey = scheme.discoverPublicKey(keyParser);
        } catch (Exception e) {
            throw new SignatureVerificationException("Failed to discover public key for scheme: " + keyParser.getScheme(), e);
        }

        // 6. Build signature base string
        byte[] signatureBase;
        try {
            signatureBase = SignatureBaseBuilder.buildSignatureBase(request, signatureInputHeader, signatureLabel);
        } catch (SignatureBaseException e) {
            throw new SignatureVerificationException("Failed to build signature base", e);
        }

        // 7. Extract signature bytes from Signature header
        byte[] signatureBytes = extractSignatureBytes(signatureHeader, signatureLabel);

        // 8. Determine algorithm: prefer alg parameter from Signature-Input, fall back to scheme
        String algorithm;
        try {
            String algFromInput = SignatureBaseBuilder.getAlgorithm(signatureInputHeader, signatureLabel);
            if (algFromInput != null && !algFromInput.isEmpty()) {
                algorithm = algFromInput;
                logger.debugf("Using algorithm from Signature-Input alg parameter: %s", algorithm);
            } else {
                algorithm = scheme.getAlgorithm(keyParser);
                logger.debugf("Using algorithm from signature scheme: %s", algorithm);
            }
        } catch (SignatureBaseException e) {
            // If parsing fails, fall back to scheme
            algorithm = scheme.getAlgorithm(keyParser);
            logger.debugf("Failed to parse algorithm from Signature-Input, using scheme default: %s", algorithm);
        }
        
        // Debug logging
        if (logger.isDebugEnabled()) {
            logger.debugf("Signature base (string): %s", new String(signatureBase, java.nio.charset.StandardCharsets.UTF_8));
            logger.debugf("Algorithm: %s", algorithm);
            logger.debugf("Public key type: %s", publicKey != null ? publicKey.getClass().getSimpleName() : "null");
            logger.debugf("Signature bytes length: %d", signatureBytes != null ? signatureBytes.length : 0);
            logger.debugf("Signature base bytes length: %d", signatureBase != null ? signatureBase.length : 0);
            // Log first few bytes of signature for debugging
            if (signatureBytes != null && signatureBytes.length > 0) {
                StringBuilder sigHex = new StringBuilder();
                int len = Math.min(16, signatureBytes.length);
                for (int i = 0; i < len; i++) {
                    sigHex.append(String.format("%02x", signatureBytes[i]));
                }
                logger.debugf("Signature bytes (first %d): %s", len, sigHex.toString());
            }
            // Log signature base bytes (hex) for debugging
            if (signatureBase != null && signatureBase.length > 0) {
                StringBuilder baseHex = new StringBuilder();
                int len = Math.min(64, signatureBase.length);
                for (int i = 0; i < len; i++) {
                    baseHex.append(String.format("%02x", signatureBase[i]));
                }
                logger.debugf("Signature base bytes (first %d): %s", len, baseHex.toString());
            }
        }
        
        boolean valid = verifySignature(signatureBase, signatureBytes, publicKey, algorithm);
        
        if (!valid) {
            logger.warnf("Signature verification failed. Signature base: %s", 
                new String(signatureBase, java.nio.charset.StandardCharsets.UTF_8));
            logger.warnf("Algorithm: %s, Public key type: %s, Signature bytes length: %d", 
                algorithm, 
                publicKey != null ? publicKey.getClass().getSimpleName() : "null",
                signatureBytes != null ? signatureBytes.length : 0);
            throw new SignatureVerificationException("Signature verification failed");
        }

        // 9. Validate Content-Digest against body (RFC 9421 Section 7.2.8)
        validateContentDigestIfRequired(request, signatureInputHeader, signatureLabel, bodyBytes);

        // 10. Extract agent identity from scheme
        String agentId = scheme.getAgentId(keyParser);

        logger.debugf("HTTP Message Signature verified successfully for agent: %s", agentId);

        return new VerificationResult(agentId, publicKey, keyParser.getScheme());
    }

    /**
     * Validate Content-Digest header against actual body if required.
     * 
     * Per RFC 9421 Section 7.2.8:
     * "Upon verification, it is important that the verifier validate not only the signature
     * but also the value of the Content-Digest field itself against the actual received content."
     */
    private void validateContentDigestIfRequired(HttpRequest request, String signatureInputHeader, 
            String signatureLabel, byte[] bodyBytes) throws SignatureVerificationException {
        
        String contentDigestHeader = request.getHttpHeaders().getHeaderString("Content-Digest");
        
        // Check if content-digest is in the covered components
        List<String> coveredComponents;
        try {
            coveredComponents = SignatureBaseBuilder.getCoveredComponents(signatureInputHeader, signatureLabel);
        } catch (SignatureBaseException e) {
            throw new SignatureVerificationException("Failed to parse covered components", e);
        }
        
        // Only validate if content-digest is a covered component
        if (!coveredComponents.contains("content-digest")) {
            logger.debugf("content-digest not in covered components, skipping body validation");
            return;
        }
        
        // Content-Digest is covered, so we MUST validate it against the body
        if (contentDigestHeader == null || contentDigestHeader.trim().isEmpty()) {
            throw new SignatureVerificationException(
                "content-digest is in covered components but Content-Digest header is missing");
        }
        
        if (bodyBytes == null) {
            logger.warnf("content-digest is in covered components but no body bytes provided for validation. " +
                "This is a security risk - body substitution attacks are possible.");
            // In strict mode, we should throw an exception here
            // For now, log a warning but allow it to proceed
            // TODO: Consider making this configurable or always strict
            return;
        }
        
        // Validate the Content-Digest against the actual body
        logger.debugf("Validating Content-Digest against body (%d bytes)", bodyBytes.length);
        ContentDigestValidator.validateContentDigest(contentDigestHeader, bodyBytes);
        logger.debugf("Content-Digest validation successful");
    }

    /**
     * Extract the signature label from the Signature header.
     * Format: label=:base64signature:
     */
    private String extractSignatureLabel(String signatureHeader) throws SignatureVerificationException {
        int equalsIndex = signatureHeader.indexOf('=');
        if (equalsIndex <= 0) {
            throw new SignatureVerificationException("Invalid Signature header format");
        }
        return signatureHeader.substring(0, equalsIndex).trim();
    }

    /**
     * Extract signature bytes from the Signature header.
     * Format: label=:base64signature:
     */
    private byte[] extractSignatureBytes(String signatureHeader, String signatureLabel) throws SignatureVerificationException {
        String labelPrefix = signatureLabel + "=:";
        int startIndex = signatureHeader.indexOf(labelPrefix);
        if (startIndex < 0) {
            throw new SignatureVerificationException("Signature label '" + signatureLabel + "' not found in Signature header");
        }

        int valueStart = startIndex + labelPrefix.length();
        int valueEnd = signatureHeader.indexOf(':', valueStart);
        if (valueEnd < 0) {
            // No trailing colon, signature extends to end
            valueEnd = signatureHeader.length();
        }

        String base64Signature = signatureHeader.substring(valueStart, valueEnd);
        logger.debugf("Extracting signature: label=%s, base64String=%s", signatureLabel, base64Signature);
        try {
            // RFC 8941 Byte Sequence uses standard Base64 encoding, not URL-safe
            byte[] decoded = Base64.getDecoder().decode(base64Signature);
            logger.debugf("Successfully decoded signature using standard Base64: %d bytes", decoded.length);
            return decoded;
        } catch (IllegalArgumentException e) {
            // Fall back to URL-safe decoder for compatibility with some implementations
            logger.debugf("Standard Base64 decode failed, trying URL-safe Base64");
            try {
                byte[] decoded = Base64.getUrlDecoder().decode(base64Signature);
                logger.debugf("Successfully decoded signature using URL-safe Base64: %d bytes", decoded.length);
                return decoded;
            } catch (IllegalArgumentException e2) {
                throw new SignatureVerificationException("Invalid base64 signature", e);
            }
        }
    }

    /**
     * Verify the signature using the public key and algorithm.
     */
    private boolean verifySignature(byte[] data, byte[] signature, PublicKey publicKey, String algorithm) 
            throws SignatureVerificationException {
        
        try {
            // Create KeyWrapper from PublicKey
            org.keycloak.crypto.KeyWrapper keyWrapper = new org.keycloak.crypto.KeyWrapper();
            keyWrapper.setPublicKey(publicKey);
            
            // Map HTTPSig algorithm names to Keycloak algorithm names
            // Ed25519 in HTTPSig maps to EdDSA in Keycloak
            String keycloakAlgorithm = algorithm;
            if ("Ed25519".equals(algorithm)) {
                keycloakAlgorithm = org.keycloak.crypto.Algorithm.EdDSA;
                keyWrapper.setCurve(org.keycloak.crypto.Algorithm.Ed25519);
            } else if ("Ed448".equals(algorithm)) {
                keycloakAlgorithm = org.keycloak.crypto.Algorithm.EdDSA;
                keyWrapper.setCurve(org.keycloak.crypto.Algorithm.Ed448);
            }
            keyWrapper.setAlgorithm(keycloakAlgorithm);
            
            // Use Keycloak's signature verification infrastructure
            org.keycloak.crypto.SignatureVerifierContext verifierContext = 
                new org.keycloak.crypto.AsymmetricSignatureVerifierContext(keyWrapper);

            return verifierContext.verify(data, signature);
            
        } catch (org.keycloak.common.VerificationException e) {
            logger.debugf(e, "Signature verification failed - VerificationException: %s", e.getMessage());
            logger.debugf("Algorithm: %s, Key type: %s, Data length: %d, Signature length: %d", 
                algorithm, publicKey != null ? publicKey.getClass().getSimpleName() : "null",
                data != null ? data.length : 0, signature != null ? signature.length : 0);
            throw new SignatureVerificationException("Signature verification failed", e);
        } catch (Exception e) {
            logger.debugf(e, "Unexpected error during signature verification: %s", e.getMessage());
            logger.debugf("Algorithm: %s, Key type: %s, Data length: %d, Signature length: %d", 
                algorithm, publicKey != null ? publicKey.getClass().getSimpleName() : "null",
                data != null ? data.length : 0, signature != null ? signature.length : 0);
            throw new SignatureVerificationException("Signature verification failed", e);
        }
    }

    /**
     * Result of signature verification.
     */
    public static class VerificationResult {
        private final String agentId;
        private final PublicKey publicKey;
        private final String scheme;

        public VerificationResult(String agentId, PublicKey publicKey, String scheme) {
            this.agentId = agentId;
            this.publicKey = publicKey;
            this.scheme = scheme;
        }

        public String getAgentId() {
            return agentId;
        }

        public PublicKey getPublicKey() {
            return publicKey;
        }

        public String getScheme() {
            return scheme;
        }
    }
}

