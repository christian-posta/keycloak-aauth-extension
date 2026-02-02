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

import org.keycloak.http.HttpRequest;
import org.keycloak.protocol.aauth.signing.exceptions.SignatureBaseException;

import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.util.ArrayList;
import java.util.Base64;
import java.util.List;

/**
 * Builds the signature base string per RFC 9421 and AAuth profile.
 * 
 * The signature base string is constructed from covered components according to
 * the Signature-Input header specification.
 * 
 * @see <a href="https://datatracker.ietf.org/doc/html/rfc9421">RFC 9421: HTTP Message Signatures</a>
 */
public class SignatureBaseBuilder {

    /**
     * Build the signature base string from the request and Signature-Input header.
     * 
     * @param request The HTTP request
     * @param signatureInput The Signature-Input header value (e.g., 'sig=("@method" "@authority" "@path" "signature-key");created=1730217600')
     * @param signatureLabel The signature label (e.g., "sig")
     * @return The signature base string as bytes
     * @throws SignatureBaseException If the signature base cannot be constructed
     */
    public static byte[] buildSignatureBase(HttpRequest request, String signatureInput, String signatureLabel) 
            throws SignatureBaseException {
        
        // Parse Signature-Input header to extract covered components and parameters
        SignatureInputParser parser = new SignatureInputParser(signatureInput, signatureLabel);
        
        List<String> components = parser.getComponents();
        List<String> signatureBase = new ArrayList<>();
        
        // Build signature base by processing each component
        for (String component : components) {
            String componentValue = getComponentValue(request, component);
            signatureBase.add("\"" + component + "\": " + componentValue);
        }
        
        // Add signature parameters (created, nonce, etc.)
        signatureBase.add("\"@signature-params\": " + buildSignatureParams(parser));
        
        // Join with newlines and convert to bytes
        String baseString = String.join("\n", signatureBase);
        return baseString.getBytes(StandardCharsets.UTF_8);
    }

    /**
     * Get the value for a covered component.
     * 
     * @param request The HTTP request
     * @param component The component name (e.g., "@method", "@authority", "@path", "signature-key")
     * @return The component value
     * @throws SignatureBaseException If the component cannot be extracted
     */
    private static String getComponentValue(HttpRequest request, String component) throws SignatureBaseException {
        switch (component) {
            case "@method":
                return request.getHttpMethod();
                
            case "@authority":
                // Use canonical authority (host:port)
                String host = request.getHttpHeaders().getHeaderString("Host");
                if (host == null) {
                    throw new SignatureBaseException("Missing Host header for @authority component");
                }
                return host;
                
            case "@path":
                // RFC 9421: @path is the absolute path of the request URI
                // Use getAbsolutePath() to get path without query/fragment
                String path = request.getUri().getAbsolutePath().getPath();
                if (path == null || path.isEmpty()) {
                    path = "/";
                }
                return path;
                
            case "@query":
                String query = request.getUri().getRequestUri().getRawQuery();
                if (query == null) {
                    query = "";
                }
                return "?" + query;
                
            case "content-type":
                String contentType = request.getHttpHeaders().getHeaderString("Content-Type");
                if (contentType == null) {
                    throw new SignatureBaseException("Missing Content-Type header but required in signature");
                }
                return contentType;
                
            case "content-digest":
                String contentDigest = request.getHttpHeaders().getHeaderString("Content-Digest");
                if (contentDigest == null) {
                    throw new SignatureBaseException("Missing Content-Digest header but required in signature");
                }
                return contentDigest;
                
            case "signature-key":
                String signatureKey = request.getHttpHeaders().getHeaderString("Signature-Key");
                if (signatureKey == null) {
                    throw new SignatureBaseException("Missing Signature-Key header but required in signature");
                }
                return signatureKey;
                
            case "nonce":
                String nonce = request.getHttpHeaders().getHeaderString("Nonce");
                if (nonce == null) {
                    throw new SignatureBaseException("Missing Nonce header but required in signature");
                }
                return nonce;
                
            default:
                // For other headers, use the header name directly
                String headerValue = request.getHttpHeaders().getHeaderString(component);
                if (headerValue == null) {
                    throw new SignatureBaseException("Missing header: " + component);
                }
                return headerValue;
        }
    }

    /**
     * Build the @signature-params value from parsed Signature-Input.
     * 
     * Per RFC 9421, the @signature-params value is the serialized signature parameters,
     * with component names quoted and space-separated inside parentheses.
     * 
     * @param parser The parsed Signature-Input
     * @return The signature-params value
     */
    private static String buildSignatureParams(SignatureInputParser parser) {
        StringBuilder sb = new StringBuilder();
        
        // Add components list with quoted component names
        sb.append("(");
        List<String> components = parser.getComponents();
        for (int i = 0; i < components.size(); i++) {
            if (i > 0) {
                sb.append(" ");
            }
            sb.append("\"").append(components.get(i)).append("\"");
        }
        sb.append(")");
        
        // Add parameters (created, nonce, etc.)
        if (parser.getCreated() != null) {
            sb.append(";created=").append(parser.getCreated());
        }
        if (parser.getNonce() != null) {
            sb.append(";nonce=").append(parser.getNonce());
        }
        
        return sb.toString();
    }

    /**
     * Calculate Content-Digest per RFC 9530.
     * 
     * @param body The request body bytes
     * @param algorithm The digest algorithm (e.g., "sha-256")
     * @return The Content-Digest header value
     * @throws SignatureBaseException If digest calculation fails
     */
    public static String calculateContentDigest(byte[] body, String algorithm) throws SignatureBaseException {
        if (body == null || body.length == 0) {
            return null;
        }
        
        try {
            MessageDigest digest;
            String algName;
            
            switch (algorithm.toLowerCase()) {
                case "sha-256":
                    digest = MessageDigest.getInstance("SHA-256");
                    algName = "sha-256";
                    break;
                case "sha-512":
                    digest = MessageDigest.getInstance("SHA-512");
                    algName = "sha-512";
                    break;
                default:
                    throw new SignatureBaseException("Unsupported digest algorithm: " + algorithm);
            }
            
            byte[] hash = digest.digest(body);
            String base64Hash = Base64.getEncoder().encodeToString(hash);
            
            return algName + "=:" + base64Hash + ":";
            
        } catch (NoSuchAlgorithmException e) {
            throw new SignatureBaseException("Failed to calculate content digest", e);
        }
    }

    /**
     * Extract the list of covered components from a Signature-Input header.
     * 
     * This is useful for determining which components are signed without
     * building the full signature base.
     * 
     * @param signatureInput The Signature-Input header value
     * @param signatureLabel The signature label (e.g., "sig")
     * @return List of covered component names
     * @throws SignatureBaseException If parsing fails
     */
    public static List<String> getCoveredComponents(String signatureInput, String signatureLabel) 
            throws SignatureBaseException {
        SignatureInputParser parser = new SignatureInputParser(signatureInput, signatureLabel);
        return parser.getComponents();
    }

    /**
     * Extract the algorithm parameter from a Signature-Input header.
     * 
     * Per RFC 9421, the algorithm can be specified via the alg parameter.
     * 
     * @param signatureInput The Signature-Input header value
     * @param signatureLabel The signature label (e.g., "sig")
     * @return The algorithm name if specified, or null if not present
     * @throws SignatureBaseException If parsing fails
     */
    public static String getAlgorithm(String signatureInput, String signatureLabel) 
            throws SignatureBaseException {
        SignatureInputParser parser = new SignatureInputParser(signatureInput, signatureLabel);
        return parser.getAlgorithm();
    }

    /**
     * Parser for Signature-Input header.
     */
    private static class SignatureInputParser {
        private final List<String> components = new ArrayList<>();
        private Long created;
        private String nonce;
        private String algorithm;

        public SignatureInputParser(String signatureInput, String signatureLabel) throws SignatureBaseException {
            // Parse format: label=("comp1" "comp2");created=123;nonce=abc
            if (signatureInput == null || signatureInput.trim().isEmpty()) {
                throw new SignatureBaseException("Signature-Input header is missing or empty");
            }

            // Find the label= part
            String labelPrefix = signatureLabel + "=";
            int labelIndex = signatureInput.indexOf(labelPrefix);
            if (labelIndex < 0) {
                throw new SignatureBaseException("Signature label '" + signatureLabel + "' not found in Signature-Input");
            }

            String value = signatureInput.substring(labelIndex + labelPrefix.length());
            
            // Extract components list (first part in parentheses)
            int parenStart = value.indexOf('(');
            int parenEnd = value.indexOf(')');
            if (parenStart < 0 || parenEnd < 0 || parenEnd <= parenStart) {
                throw new SignatureBaseException("Invalid component list in Signature-Input");
            }

            String componentsStr = value.substring(parenStart + 1, parenEnd);
            // Parse quoted component names
            String[] comps = componentsStr.split("\"");
            for (String comp : comps) {
                comp = comp.trim();
                if (!comp.isEmpty() && !comp.equals(" ")) {
                    components.add(comp);
                }
            }

            // Extract parameters (after the closing parenthesis)
            String params = value.substring(parenEnd + 1);
            String[] paramParts = params.split(";");
            for (String param : paramParts) {
                param = param.trim();
                if (param.startsWith("created=")) {
                    created = Long.parseLong(param.substring(8));
                } else if (param.startsWith("nonce=")) {
                    nonce = param.substring(6);
                } else if (param.startsWith("alg=")) {
                    // RFC 9421: alg parameter specifies the signature algorithm
                    algorithm = param.substring(4).trim();
                    // Remove quotes if present
                    if (algorithm.startsWith("\"") && algorithm.endsWith("\"")) {
                        algorithm = algorithm.substring(1, algorithm.length() - 1);
                    }
                }
            }
        }

        public List<String> getComponents() {
            return components;
        }

        public Long getCreated() {
            return created;
        }

        public String getNonce() {
            return nonce;
        }

        public String getAlgorithm() {
            return algorithm;
        }
    }
}

