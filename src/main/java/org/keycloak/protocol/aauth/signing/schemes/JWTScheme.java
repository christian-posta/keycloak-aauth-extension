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

package org.keycloak.protocol.aauth.signing.schemes;

import org.jboss.logging.Logger;
import org.keycloak.jose.jwk.JWK;
import org.keycloak.jose.jwk.JWKParser;
import org.keycloak.jose.jwk.JSONWebKeySet;
import org.keycloak.jose.jws.JWSInput;
import org.keycloak.models.KeycloakSession;
import org.keycloak.protocol.aauth.metadata.AgentMetadata;
import org.keycloak.protocol.aauth.metadata.MetadataFetcher;
import org.keycloak.protocol.aauth.signing.SignatureKeyParser;
import org.keycloak.protocol.aauth.signing.exceptions.SignatureVerificationException;
import org.keycloak.protocol.aauth.tokens.AgentTokenValidator;
import org.keycloak.protocol.aauth.tokens.AuthTokenValidator;
import org.keycloak.representations.JsonWebToken;

import java.io.UnsupportedEncodingException;
import java.net.URLDecoder;
import java.security.PublicKey;
import java.util.HashMap;
import java.util.Map;

/**
 * Signature scheme handler for scheme=jwt.
 * 
 * Validates either an agent token (agent+jwt) or auth token (auth+jwt),
 * then extracts the public key for HTTP signature verification.
 * 
 * For token exchange requests (request_type=exchange), the public key is
 * discovered from the requester's JWKS, not from cnf.jwk.
 */
public class JWTScheme implements SignatureScheme {

    private static final Logger logger = Logger.getLogger(JWTScheme.class);
    
    private final KeycloakSession session;
    
    // Cached values for token exchange
    private String tokenExchangeRequesterId;
    private JWK tokenExchangeRequesterJwk;

    public JWTScheme(KeycloakSession session) {
        this.session = session;
    }

    @Override
    public PublicKey discoverPublicKey(SignatureKeyParser keyParser) throws Exception {
        String jwtString = keyParser.getJWT();
        
        if (jwtString == null) {
            throw new SignatureVerificationException("Missing 'jwt' parameter in Signature-Key for scheme=jwt");
        }

        // Parse JWT
        JWSInput jws;
        try {
            jws = new JWSInput(jwtString);
        } catch (org.keycloak.jose.jws.JWSInputException e) {
            throw new SignatureVerificationException("Failed to parse JWT in scheme=jwt", e);
        }
        
        // Determine token type from typ header
        String typ = jws.getHeader().getType();
        
        if ("agent+jwt".equals(typ)) {
            // Validate agent token and extract cnf.jwk
            AgentTokenValidator validator = new AgentTokenValidator(session);
            Map<String, Object> cnf = validator.validateAndExtractCnf(jwtString);
            return extractPublicKeyFromCnf(cnf);
            
        } else if ("auth+jwt".equals(typ)) {
            // Validate auth token (with JWT signature verification)
            AuthTokenValidator validator = new AuthTokenValidator(session);
            AuthTokenValidator.AuthTokenValidationResult validationResult = validator.validateAuthToken(jwtString);
            
            // Store the full JWT string in session for token exchange
            session.setAttribute("aauth.upstream.auth.token", jwtString);
            
            // Check if this is a token exchange request
            if (isTokenExchangeRequest()) {
                logger.debug("Token exchange request detected, discovering requester's public key");
                return discoverRequesterPublicKeyForExchange(validationResult);
            }
            
            // For non-exchange requests, use cnf.jwk from the auth token
            return extractPublicKeyFromCnf(validationResult.getCnf());
            
        } else {
            throw new SignatureVerificationException("Unsupported JWT type in scheme=jwt: " + typ);
        }
    }

    /**
     * Check if the current request is a token exchange request.
     * Parses form data from body bytes stored in session.
     */
    private boolean isTokenExchangeRequest() {
        Map<String, String> formParams = parseFormData();
        if (formParams == null) {
            return false;
        }
        String requestType = formParams.get("request_type");
        return "exchange".equals(requestType);
    }

    /**
     * Parse URL-encoded form data from body bytes stored in session.
     */
    private Map<String, String> parseFormData() {
        byte[] bodyBytes = (byte[]) session.getAttribute("aauth.request.body.bytes");
        if (bodyBytes == null || bodyBytes.length == 0) {
            return null;
        }
        
        try {
            String body = new String(bodyBytes, "UTF-8");
            Map<String, String> params = new HashMap<>();
            
            for (String param : body.split("&")) {
                String[] keyValue = param.split("=", 2);
                if (keyValue.length == 2) {
                    String key = URLDecoder.decode(keyValue[0], "UTF-8");
                    String value = URLDecoder.decode(keyValue[1], "UTF-8");
                    params.put(key, value);
                }
            }
            
            return params;
        } catch (UnsupportedEncodingException e) {
            logger.warn("Failed to parse form data", e);
            return null;
        }
    }

    /**
     * Discover the requester's public key for token exchange.
     * 
     * Per AAuth spec Section 9.10:
     * 1. Validate upstream token's aud matches resource token's agent
     * 2. Use that agent URL to fetch their JWKS
     * 3. Find the key matching agent_jkt from resource token
     */
    private PublicKey discoverRequesterPublicKeyForExchange(AuthTokenValidator.AuthTokenValidationResult validationResult) 
            throws SignatureVerificationException {
        
        // Get the audience from upstream auth token
        String[] audiences = validationResult.getAudience();
        if (audiences == null || audiences.length == 0) {
            throw new SignatureVerificationException("Missing 'aud' claim in upstream auth token for token exchange");
        }
        String upstreamAud = audiences[0];
        logger.debugf("Token exchange: upstream auth token aud = %s", upstreamAud);
        
        // Parse form data to get resource_token
        Map<String, String> formParams = parseFormData();
        if (formParams == null) {
            throw new SignatureVerificationException("Failed to parse form data for token exchange");
        }
        
        String resourceTokenString = formParams.get("resource_token");
        if (resourceTokenString == null || resourceTokenString.isEmpty()) {
            throw new SignatureVerificationException("Missing resource_token parameter for token exchange");
        }
        
        // Parse resource token to extract agent and agent_jkt
        JWSInput resourceJws;
        try {
            resourceJws = new JWSInput(resourceTokenString);
        } catch (org.keycloak.jose.jws.JWSInputException e) {
            throw new SignatureVerificationException("Failed to parse resource token", e);
        }
        
        JsonWebToken resourceToken;
        try {
            resourceToken = resourceJws.readJsonContent(JsonWebToken.class);
        } catch (org.keycloak.jose.jws.JWSInputException e) {
            throw new SignatureVerificationException("Failed to read resource token claims", e);
        }
        
        Map<String, Object> resourceClaims = resourceToken.getOtherClaims();
        String resourceAgent = (String) resourceClaims.get("agent");
        String agentJkt = (String) resourceClaims.get("agent_jkt");
        
        logger.debugf("Token exchange: resource token agent = %s, agent_jkt = %s", resourceAgent, agentJkt);
        
        if (resourceAgent == null) {
            throw new SignatureVerificationException("Missing 'agent' claim in resource token");
        }
        
        if (agentJkt == null) {
            throw new SignatureVerificationException("Missing 'agent_jkt' claim in resource token");
        }
        
        // Cross-validate: upstream token's aud must match resource token's agent
        if (!upstreamAud.equals(resourceAgent)) {
            throw new SignatureVerificationException(
                "Token exchange validation failed: upstream token aud (" + upstreamAud + 
                ") does not match resource token agent (" + resourceAgent + ")");
        }
        
        logger.debugf("Token exchange: cross-validation passed, requester = %s", resourceAgent);
        
        // Store the requester ID for getAgentId()
        this.tokenExchangeRequesterId = resourceAgent;
        
        // Fetch requester's agent metadata
        MetadataFetcher fetcher = new MetadataFetcher(session);
        AgentMetadata agentMetadata = fetcher.fetchAgentMetadata(resourceAgent, "aauth-agent");
        
        if (agentMetadata == null || agentMetadata.getJwksUri() == null) {
            throw new SignatureVerificationException(
                "Failed to fetch agent metadata or jwks_uri for requester: " + resourceAgent);
        }
        
        logger.debugf("Token exchange: fetching requester JWKS from %s", agentMetadata.getJwksUri());
        
        // Fetch JWKS
        JSONWebKeySet jwks = fetcher.fetchJWKS(agentMetadata.getJwksUri());
        if (jwks == null || jwks.getKeys() == null || jwks.getKeys().length == 0) {
            throw new SignatureVerificationException(
                "Failed to fetch JWKS or no keys found for requester: " + resourceAgent);
        }
        
        // Find key matching agent_jkt
        JWK matchingKey = null;
        for (JWK jwk : jwks.getKeys()) {
            String thumbprint = calculateJwkThumbprint(jwk);
            logger.debugf("Token exchange: checking JWK kid=%s, thumbprint=%s", jwk.getKeyId(), thumbprint);
            if (agentJkt.equals(thumbprint)) {
                matchingKey = jwk;
                break;
            }
        }
        
        if (matchingKey == null) {
            throw new SignatureVerificationException(
                "No key matching agent_jkt (" + agentJkt + ") found in requester's JWKS");
        }
        
        logger.debugf("Token exchange: found matching key, kid=%s", matchingKey.getKeyId());
        
        // Cache the JWK for getAlgorithm()
        this.tokenExchangeRequesterJwk = matchingKey;
        
        return JWKParser.create(matchingKey).toPublicKey();
    }

    /**
     * Calculate JWK thumbprint per RFC 7638.
     */
    private String calculateJwkThumbprint(JWK jwk) throws SignatureVerificationException {
        try {
            // Build canonical JSON representation based on key type
            String kty = jwk.getKeyType();
            StringBuilder canonical = new StringBuilder();
            
            if ("OKP".equals(kty)) {
                // For OKP keys: {"crv":"...","kty":"OKP","x":"..."}
                String crv = (String) jwk.getOtherClaims().get("crv");
                String x = (String) jwk.getOtherClaims().get("x");
                canonical.append("{\"crv\":\"").append(crv)
                        .append("\",\"kty\":\"").append(kty)
                        .append("\",\"x\":\"").append(x).append("\"}");
            } else if ("EC".equals(kty)) {
                // For EC keys: {"crv":"...","kty":"EC","x":"...","y":"..."}
                String crv = (String) jwk.getOtherClaims().get("crv");
                String x = (String) jwk.getOtherClaims().get("x");
                String y = (String) jwk.getOtherClaims().get("y");
                canonical.append("{\"crv\":\"").append(crv)
                        .append("\",\"kty\":\"").append(kty)
                        .append("\",\"x\":\"").append(x)
                        .append("\",\"y\":\"").append(y).append("\"}");
            } else if ("RSA".equals(kty)) {
                // For RSA keys: {"e":"...","kty":"RSA","n":"..."}
                String e = (String) jwk.getOtherClaims().get("e");
                String n = (String) jwk.getOtherClaims().get("n");
                canonical.append("{\"e\":\"").append(e)
                        .append("\",\"kty\":\"").append(kty)
                        .append("\",\"n\":\"").append(n).append("\"}");
            } else {
                throw new SignatureVerificationException("Unsupported key type for thumbprint: " + kty);
            }
            
            // Calculate SHA-256 hash
            java.security.MessageDigest digest = java.security.MessageDigest.getInstance("SHA-256");
            byte[] hash = digest.digest(canonical.toString().getBytes("UTF-8"));
            
            // Base64url encode without padding
            return java.util.Base64.getUrlEncoder().withoutPadding().encodeToString(hash);
            
        } catch (Exception e) {
            throw new SignatureVerificationException("Failed to calculate JWK thumbprint", e);
        }
    }

    /**
     * Extract public key from cnf.jwk claim.
     */
    private PublicKey extractPublicKeyFromCnf(Map<String, Object> cnf) throws Exception {
        @SuppressWarnings("unchecked")
        Map<String, Object> jwkMap = (Map<String, Object>) cnf.get("jwk");
        
        if (jwkMap == null) {
            throw new SignatureVerificationException("Missing cnf.jwk claim in JWT");
        }

        // Convert map to JWK JSON and parse
        String jwkJson = org.keycloak.util.JsonSerialization.writeValueAsString(jwkMap);
        JWK jwk = org.keycloak.util.JsonSerialization.readValue(jwkJson, JWK.class);
        
        return JWKParser.create(jwk).toPublicKey();
    }

    @Override
    public String getAlgorithm(SignatureKeyParser keyParser) {
        // For token exchange, use the cached requester JWK
        if (tokenExchangeRequesterJwk != null) {
            return getAlgorithmFromJwk(tokenExchangeRequesterJwk);
        }
        
        // For scheme=jwt, the HTTP request is signed by the agent's key from cnf.jwk,
        // NOT by the auth server's key used to sign the JWT itself.
        // We must extract the algorithm from the cnf.jwk claim.
        try {
            String jwtString = keyParser.getJWT();
            if (jwtString == null) {
                return "Ed25519"; // Default
            }
            
            // Parse JWT to extract cnf.jwk
            JWSInput jws = new JWSInput(jwtString);
            JsonWebToken token = jws.readJsonContent(JsonWebToken.class);
            
            Map<String, Object> otherClaims = token.getOtherClaims();
            if (otherClaims == null) {
                return "Ed25519"; // Default
            }
            
            @SuppressWarnings("unchecked")
            Map<String, Object> cnf = (Map<String, Object>) otherClaims.get("cnf");
            if (cnf == null) {
                return "Ed25519"; // Default
            }
            
            @SuppressWarnings("unchecked")
            Map<String, Object> jwk = (Map<String, Object>) cnf.get("jwk");
            if (jwk == null) {
                return "Ed25519"; // Default
            }
            
            // Determine algorithm from JWK properties
            String kty = (String) jwk.get("kty");
            String crv = (String) jwk.get("crv");
            String alg = (String) jwk.get("alg");
            
            // If explicit algorithm is in JWK, use it
            if (alg != null) {
                if ("EdDSA".equals(alg)) {
                    return "Ed25519"; // HTTPSig uses curve name
                }
                return alg;
            }
            
            // Infer algorithm from key type and curve
            if ("OKP".equals(kty)) {
                // Edwards curves
                if ("Ed25519".equals(crv)) {
                    return "Ed25519";
                } else if ("Ed448".equals(crv)) {
                    return "Ed448";
                }
            } else if ("EC".equals(kty)) {
                // ECDSA curves
                if ("P-256".equals(crv)) {
                    return "ES256";
                } else if ("P-384".equals(crv)) {
                    return "ES384";
                } else if ("P-521".equals(crv)) {
                    return "ES512";
                }
            } else if ("RSA".equals(kty)) {
                return "RS256"; // Default RSA algorithm
            }
            
            return "Ed25519"; // Default fallback
        } catch (Exception e) {
            return "Ed25519"; // Default on error
        }
    }

    /**
     * Get algorithm from a JWK.
     */
    private String getAlgorithmFromJwk(JWK jwk) {
        String kty = jwk.getKeyType();
        String alg = jwk.getAlgorithm();
        
        // If explicit algorithm is in JWK, use it
        if (alg != null) {
            if ("EdDSA".equals(alg)) {
                return "Ed25519"; // HTTPSig uses curve name
            }
            return alg;
        }
        
        // Infer algorithm from key type and curve
        String crv = (String) jwk.getOtherClaims().get("crv");
        
        if ("OKP".equals(kty)) {
            if ("Ed25519".equals(crv)) {
                return "Ed25519";
            } else if ("Ed448".equals(crv)) {
                return "Ed448";
            }
        } else if ("EC".equals(kty)) {
            if ("P-256".equals(crv)) {
                return "ES256";
            } else if ("P-384".equals(crv)) {
                return "ES384";
            } else if ("P-521".equals(crv)) {
                return "ES512";
            }
        } else if ("RSA".equals(kty)) {
            return "RS256";
        }
        
        return "Ed25519"; // Default
    }

    @Override
    public String getAgentId(SignatureKeyParser keyParser) {
        // For token exchange, return the cached requester ID
        if (tokenExchangeRequesterId != null) {
            return tokenExchangeRequesterId;
        }
        
        try {
            String jwtString = keyParser.getJWT();
            if (jwtString == null) {
                return null;
            }
            
            // Parse JWT to extract agent ID
            JWSInput jws = new JWSInput(jwtString);
            JsonWebToken token = jws.readJsonContent(JsonWebToken.class);
            String typ = jws.getHeader().getType();
            
            if ("agent+jwt".equals(typ)) {
                // For agent tokens, agent ID is the issuer
                return token.getIssuer();
            } else if ("auth+jwt".equals(typ)) {
                // For auth tokens, agent ID is in the 'agent' claim
                // If 'agent' claim is missing, fall back to 'aud' claim
                // (this happens when agent acts as its own resource, i.e., aud == agent)
                Map<String, Object> otherClaims = token.getOtherClaims();
                if (otherClaims != null) {
                    Object agent = otherClaims.get("agent");
                    if (agent instanceof String) {
                        return (String) agent;
                    }
                }
                
                // Fall back to audience (aud) for agent-as-resource case
                // Per AAuth spec, when agent == aud, the 'agent' claim may be omitted
                String[] audiences = token.getAudience();
                if (audiences != null && audiences.length > 0) {
                    return audiences[0];
                }
            }
            
            return null;
        } catch (Exception e) {
            return null;
        }
    }
}

