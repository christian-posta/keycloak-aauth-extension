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
import org.keycloak.protocol.aauth.signing.exceptions.SignatureVerificationException;

import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.util.Base64;
import java.util.HashMap;
import java.util.Map;

/**
 * Validates Content-Digest header values against actual request body per RFC 9530.
 * 
 * RFC 9530 defines the Content-Digest field format as a Structured Field Dictionary
 * where each key is an algorithm name and each value is a Byte Sequence containing
 * the digest value.
 * 
 * Format: algorithm=:base64digest:
 * Example: sha-256=:X48E9qOokqqrvdts8nOJRJN3OWDUoyWxBf7kbu9DBPE=:
 * 
 * Per RFC 9421 Section 7.2.8, verifiers MUST validate Content-Digest against the
 * actual received content to prevent body substitution attacks.
 * 
 * @see <a href="https://datatracker.ietf.org/doc/html/rfc9530">RFC 9530: Digest Fields</a>
 * @see <a href="https://datatracker.ietf.org/doc/html/rfc9421#section-7.2.8">RFC 9421 Section 7.2.8</a>
 */
public class ContentDigestValidator {

    private static final Logger logger = Logger.getLogger(ContentDigestValidator.class);

    /**
     * Maximum body size to validate (10MB). Requests with larger bodies should
     * be rejected or handled specially by the application.
     */
    public static final int MAX_BODY_SIZE = 10 * 1024 * 1024;

    /**
     * Validates the Content-Digest header value against the actual request body.
     * 
     * Per RFC 9421 Section 7.2.8, this validation is critical to prevent body
     * substitution attacks where an attacker modifies the body but leaves the
     * Content-Digest header unchanged.
     * 
     * @param contentDigestHeader The Content-Digest header value (e.g., "sha-256=:base64:") 
     * @param body The actual request body bytes
     * @throws SignatureVerificationException If validation fails or digest doesn't match
     */
    public static void validateContentDigest(String contentDigestHeader, byte[] body) 
            throws SignatureVerificationException {
        
        if (contentDigestHeader == null || contentDigestHeader.trim().isEmpty()) {
            throw new SignatureVerificationException("Content-Digest header is missing or empty");
        }

        if (body == null) {
            body = new byte[0];
        }

        // Parse the Content-Digest header to extract algorithm(s) and digest value(s)
        Map<String, String> digests = parseContentDigestHeader(contentDigestHeader);
        
        if (digests.isEmpty()) {
            throw new SignatureVerificationException("No valid digest found in Content-Digest header");
        }

        // Validate against at least one supported algorithm
        boolean validated = false;
        StringBuilder errors = new StringBuilder();
        
        for (Map.Entry<String, String> entry : digests.entrySet()) {
            String algorithm = entry.getKey();
            String expectedDigest = entry.getValue();
            
            try {
                String actualDigest = calculateDigest(body, algorithm);
                
                // Use constant-time comparison to prevent timing attacks
                if (constantTimeEquals(expectedDigest, actualDigest)) {
                    logger.debugf("Content-Digest validated successfully using %s", algorithm);
                    validated = true;
                    break;
                } else {
                    errors.append(String.format("Algorithm %s: expected %s, got %s; ", 
                        algorithm, expectedDigest, actualDigest));
                }
            } catch (SignatureVerificationException e) {
                // Unsupported algorithm, try next one
                logger.debugf("Skipping unsupported algorithm in Content-Digest: %s", algorithm);
            }
        }
        
        if (!validated) {
            throw new SignatureVerificationException(
                "Content-Digest validation failed: digest does not match body. " + errors.toString());
        }
    }

    /**
     * Parses the Content-Digest header per RFC 9530/RFC 8941 Structured Fields.
     * 
     * Format: algorithm=:base64value:
     * Multiple: sha-256=:...:, sha-512=:...:
     * 
     * @param header The Content-Digest header value
     * @return Map of algorithm name to base64-encoded digest value
     */
    static Map<String, String> parseContentDigestHeader(String header) {
        Map<String, String> digests = new HashMap<>();
        
        if (header == null || header.trim().isEmpty()) {
            return digests;
        }

        // Split by comma for multiple digests (RFC 8941 Dictionary)
        String[] parts = header.split(",");
        
        for (String part : parts) {
            part = part.trim();
            
            // Format: algorithm=:base64value:
            int equalsIndex = part.indexOf('=');
            if (equalsIndex <= 0) {
                continue;
            }
            
            String algorithm = part.substring(0, equalsIndex).trim().toLowerCase();
            String value = part.substring(equalsIndex + 1).trim();
            
            // RFC 8941 Byte Sequence format: :base64:
            if (value.startsWith(":") && value.endsWith(":") && value.length() > 2) {
                String base64Value = value.substring(1, value.length() - 1);
                digests.put(algorithm, base64Value);
            }
        }
        
        return digests;
    }

    /**
     * Calculates the digest of the given body using the specified algorithm.
     * 
     * Only "Active" algorithms from RFC 9530 are supported:
     * - sha-256 (SHA-256)
     * - sha-512 (SHA-512)
     * 
     * @param body The body bytes to digest
     * @param algorithm The algorithm name (e.g., "sha-256")
     * @return Base64-encoded digest value
     * @throws SignatureVerificationException If algorithm is unsupported
     */
    static String calculateDigest(byte[] body, String algorithm) throws SignatureVerificationException {
        try {
            MessageDigest digest;
            
            switch (algorithm.toLowerCase()) {
                case "sha-256":
                    digest = MessageDigest.getInstance("SHA-256");
                    break;
                case "sha-512":
                    digest = MessageDigest.getInstance("SHA-512");
                    break;
                default:
                    throw new SignatureVerificationException(
                        "Unsupported Content-Digest algorithm: " + algorithm + 
                        ". Only sha-256 and sha-512 are supported per RFC 9530.");
            }
            
            byte[] hash = digest.digest(body);
            return Base64.getEncoder().encodeToString(hash);
            
        } catch (NoSuchAlgorithmException e) {
            throw new SignatureVerificationException("Failed to calculate digest: " + e.getMessage(), e);
        }
    }

    /**
     * Constant-time string comparison to prevent timing attacks.
     * 
     * @param a First string
     * @param b Second string
     * @return true if strings are equal
     */
    private static boolean constantTimeEquals(String a, String b) {
        if (a == null || b == null) {
            return a == b;
        }
        
        if (a.length() != b.length()) {
            return false;
        }
        
        int result = 0;
        for (int i = 0; i < a.length(); i++) {
            result |= a.charAt(i) ^ b.charAt(i);
        }
        return result == 0;
    }

    /**
     * Checks if Content-Digest validation should be performed.
     * 
     * @param contentDigestHeader The Content-Digest header value (may be null)
     * @param coveredComponents List of covered component names from Signature-Input
     * @return true if Content-Digest should be validated
     */
    public static boolean shouldValidateContentDigest(String contentDigestHeader, 
                                                       java.util.List<String> coveredComponents) {
        // Validate if content-digest is in the covered components AND the header is present
        return contentDigestHeader != null && 
               !contentDigestHeader.trim().isEmpty() &&
               coveredComponents != null &&
               coveredComponents.contains("content-digest");
    }
}
