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
import org.keycloak.protocol.aauth.signing.exceptions.SignatureKeyParseException;

import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

/**
 * Parser for the Signature-Key header per RFC 8941 Structured Fields.
 * 
 * The Signature-Key header is a Dictionary (structured field) with a single member.
 * Example: Signature-Key: sig=hwk;kty="OKP";crv="Ed25519";x="JrQLj5P..."
 * 
 * @see <a href="https://datatracker.ietf.org/doc/html/rfc8941">RFC 8941: Structured Field Values for HTTP</a>
 */
public class SignatureKeyParser {

    private static final Logger logger = Logger.getLogger(SignatureKeyParser.class);

    private final String signatureLabel;
    private final String scheme;
    private final Map<String, String> parameters;

    /**
     * Parse a Signature-Key header value.
     * 
     * Supports two RFC 8941 formats:
     * 1. Semicolon-separated: sig=jwks;id="...";kid="..."
     * 2. Parenthesized inner-list: sig=(scheme=jwks id="..." kid="...")
     * 
     * @param signatureKeyHeader The Signature-Key header value
     * @throws SignatureKeyParseException If the header cannot be parsed
     */
    public SignatureKeyParser(String signatureKeyHeader) throws SignatureKeyParseException {
        if (signatureKeyHeader == null || signatureKeyHeader.trim().isEmpty()) {
            throw new SignatureKeyParseException("Signature-Key header is missing or empty");
        }

        String trimmed = signatureKeyHeader.trim();
        int equalsIndex = trimmed.indexOf('=');
        if (equalsIndex <= 0) {
            throw new SignatureKeyParseException("Invalid Signature-Key format: missing label=value");
        }

        // Extract signature label (e.g., "sig")
        this.signatureLabel = trimmed.substring(0, equalsIndex).trim();
        
        // Extract value and parameters
        String valueAndParams = trimmed.substring(equalsIndex + 1).trim();
        
        // Check if it's parenthesized format: sig=(scheme=jwks id="..." kid="...")
        if (valueAndParams.startsWith("(")) {
            // Find matching closing parenthesis, handling quoted strings
            int closingParen = findMatchingClosingParen(valueAndParams, 0);
            if (closingParen < 0) {
                throw new SignatureKeyParseException("Invalid Signature-Key format: unmatched opening parenthesis");
            }
            
            // Extract content inside parentheses
            String innerContent = valueAndParams.substring(1, closingParen).trim();
            
            // Parse space-separated parameters: scheme=jwks id="..." kid="..."
            this.parameters = new HashMap<>();
            String[] paramParts = parseSpaceSeparatedParams(innerContent);
            
            // Extract scheme from first parameter (scheme=jwks)
            String schemeParam = paramParts.length > 0 ? paramParts[0] : null;
            if (schemeParam == null || !schemeParam.startsWith("scheme=")) {
                throw new SignatureKeyParseException("Invalid Signature-Key format: missing scheme parameter in parenthesized format");
            }
            this.scheme = parseValue(schemeParam.substring(7).trim()); // Extract value after "scheme="
            
            // Parse remaining parameters
            for (int i = 1; i < paramParts.length; i++) {
                String param = paramParts[i].trim();
                if (param.isEmpty()) {
                    continue;
                }
                
                int paramEquals = param.indexOf('=');
                if (paramEquals <= 0) {
                    throw new SignatureKeyParseException("Invalid parameter format: " + param);
                }
                
                String paramName = param.substring(0, paramEquals).trim();
                String paramValue = parseValue(param.substring(paramEquals + 1).trim());
                parameters.put(paramName, paramValue);
            }
        } else {
            // Standard semicolon-separated format: sig=jwks;id="...";kid="..."
            String[] parts = valueAndParams.split(";", -1);
            
            if (parts.length == 0) {
                throw new SignatureKeyParseException("Invalid Signature-Key format: missing value");
            }

            // First part is the scheme value (hwk, jwks, x509, jwt)
            this.scheme = parseValue(parts[0].trim());
            
            // Remaining parts are parameters
            this.parameters = new HashMap<>();
            for (int i = 1; i < parts.length; i++) {
                String param = parts[i].trim();
                if (param.isEmpty()) {
                    continue;
                }
                
                int paramEquals = param.indexOf('=');
                if (paramEquals <= 0) {
                    throw new SignatureKeyParseException("Invalid parameter format: " + param);
                }
                
                String paramName = param.substring(0, paramEquals).trim();
                String paramValue = parseValue(param.substring(paramEquals + 1).trim());
                parameters.put(paramName, paramValue);
            }
        }
        
        logger.debugf("SignatureKeyParser: parsed header - label=%s, scheme=%s, parameters=%s", 
                signatureLabel, scheme, parameters);
    }

    /**
     * Find the matching closing parenthesis, handling quoted strings.
     * 
     * @param str The string to search
     * @param startPos The position of the opening parenthesis
     * @return The position of the matching closing parenthesis, or -1 if not found
     */
    private int findMatchingClosingParen(String str, int startPos) {
        int depth = 0;
        boolean inQuotes = false;
        boolean escapeNext = false;
        
        for (int i = startPos; i < str.length(); i++) {
            char c = str.charAt(i);
            
            if (escapeNext) {
                escapeNext = false;
                continue;
            }
            
            if (c == '\\') {
                escapeNext = true;
                continue;
            }
            
            if (c == '"' && !escapeNext) {
                inQuotes = !inQuotes;
                continue;
            }
            
            if (inQuotes) {
                continue;
            }
            
            if (c == '(') {
                depth++;
            } else if (c == ')') {
                depth--;
                if (depth == 0) {
                    return i;
                }
            }
        }
        
        return -1;
    }

    /**
     * Parse space-separated parameters, handling quoted strings.
     * 
     * @param content The content to parse (e.g., "scheme=jwks id=\"...\" kid=\"...\"")
     * @return Array of parameter strings
     */
    private String[] parseSpaceSeparatedParams(String content) {
        List<String> params = new ArrayList<>();
        StringBuilder current = new StringBuilder();
        boolean inQuotes = false;
        boolean escapeNext = false;
        
        for (int i = 0; i < content.length(); i++) {
            char c = content.charAt(i);
            
            if (escapeNext) {
                current.append(c);
                escapeNext = false;
                continue;
            }
            
            if (c == '\\') {
                escapeNext = true;
                current.append(c);
                continue;
            }
            
            if (c == '"') {
                inQuotes = !inQuotes;
                current.append(c);
                continue;
            }
            
            if (c == ' ' && !inQuotes) {
                if (current.length() > 0) {
                    params.add(current.toString());
                    current.setLength(0);
                }
            } else {
                current.append(c);
            }
        }
        
        if (current.length() > 0) {
            params.add(current.toString());
        }
        
        return params.toArray(new String[0]);
    }

    /**
     * Parse a structured field value, handling quoted strings and bare items.
     * 
     * @param value The value to parse
     * @return The parsed value (quotes removed if present)
     */
    private String parseValue(String value) {
        if (value == null || value.isEmpty()) {
            return value;
        }
        
        // Remove quotes if present
        if (value.startsWith("\"") && value.endsWith("\"")) {
            return value.substring(1, value.length() - 1);
        }
        
        return value;
    }

    /**
     * Get the signature label (e.g., "sig").
     * 
     * @return The signature label
     */
    public String getSignatureLabel() {
        return signatureLabel;
    }

    /**
     * Get the scheme (hwk, jwks, x509, or jwt).
     * 
     * @return The scheme
     */
    public String getScheme() {
        return scheme;
    }

    /**
     * Get a parameter value by name.
     * 
     * @param name Parameter name
     * @return Parameter value, or null if not present
     */
    public String getParameter(String name) {
        return parameters.get(name);
    }

    /**
     * Get all parameters.
     * 
     * @return Map of parameter names to values
     */
    public Map<String, String> getParameters() {
        return new HashMap<>(parameters);
    }

    /**
     * Get the agent identifier (for scheme=jwks Mode 2: Identifier + Metadata).
     * 
     * @return Agent identifier (HTTPS URL), or null if not present
     */
    public String getAgentId() {
        return getParameter("id");
    }

    /**
     * Get the key identifier (kid).
     * 
     * @return Key identifier, or null if not present
     */
    public String getKid() {
        return getParameter("kid");
    }

    /**
     * Get the well-known document name (for scheme=jwks Mode 2: Identifier + Metadata).
     * 
     * @return Well-known document name (e.g., "aauth-agent"), or null if not present
     */
    public String getWellKnown() {
        return getParameter("well-known");
    }

    /**
     * Get the JWT token (for scheme=jwt).
     * 
     * @return JWT token string, or null if not present
     */
    public String getJWT() {
        return getParameter("jwt");
    }

    /**
     * Get the certificate URL (x5u) for scheme=x509.
     * 
     * @return Certificate URL, or null if not present
     */
    public String getX5u() {
        return getParameter("x5u");
    }

    /**
     * Get the certificate thumbprint (x5t) for scheme=x509.
     * 
     * @return Certificate thumbprint, or null if not present
     */
    public String getX5t() {
        return getParameter("x5t");
    }

    /**
     * Get JWK parameters (for scheme=hwk).
     * Extracts standard JWK parameters (kty, kid, alg, use) and key-type-specific parameters
     * (crv, x, y, n, e, d, p, q, dp, dq, qi) from the Signature-Key header.
     * 
     * @return Map of JWK parameter names to values
     */
    public Map<String, String> getJWKParameters() {
        Map<String, String> jwkParams = new HashMap<>();
        // Standard JWK parameters (RFC 7517)
        String[] standardJWKParams = {"kty", "kid", "alg", "use"};
        // Key-type-specific parameters
        String[] keySpecificParams = {"crv", "x", "y", "n", "e", "d", "p", "q", "dp", "dq", "qi"};
        
        // Combine both arrays
        String[] allJWKParams = new String[standardJWKParams.length + keySpecificParams.length];
        System.arraycopy(standardJWKParams, 0, allJWKParams, 0, standardJWKParams.length);
        System.arraycopy(keySpecificParams, 0, allJWKParams, standardJWKParams.length, keySpecificParams.length);
        
        for (String paramName : allJWKParams) {
            String value = getParameter(paramName);
            if (value != null) {
                jwkParams.put(paramName, value);
            }
        }
        
        return jwkParams;
    }
}

