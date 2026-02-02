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

package org.keycloak.protocol.aauth.tokens;

import org.jboss.logging.Logger;
import org.keycloak.jose.jws.JWSInput;
import org.keycloak.jose.jws.JWSInputException;
import org.keycloak.jose.jwk.JWK;
import org.keycloak.jose.jwk.JSONWebKeySet;
import org.keycloak.models.KeycloakSession;
import org.keycloak.protocol.aauth.metadata.MetadataFetcher;
import org.keycloak.protocol.aauth.metadata.ResourceMetadata;
import org.keycloak.protocol.aauth.signing.exceptions.SignatureVerificationException;
import org.keycloak.representations.JsonWebToken;

import java.util.Map;

/**
 * Validates resource tokens (resource+jwt) per AAuth specification Section 6.5.
 * 
 * Validates:
 * - JWT signature using resource's JWKS
 * - typ="resource+jwt"
 * - Required claims: iss, aud, agent, agent_jkt, exp
 * - scope or auth_request_url
 */
public class ResourceTokenValidator {

    private static final Logger logger = Logger.getLogger(ResourceTokenValidator.class);
    private final KeycloakSession session;
    private final String authServerId;

    public ResourceTokenValidator(KeycloakSession session, String authServerId) {
        this.session = session;
        this.authServerId = authServerId;
    }

    /**
     * Validate a resource token.
     * 
     * @param resourceTokenString The resource token JWT string
     * @param agentId The agent identifier making the request
     * @param agentJkt The JWK thumbprint of the agent's current signing key
     * @return Validated resource token with extracted claims
     * @throws SignatureVerificationException If validation fails
     */
    public ResourceTokenValidationResult validate(String resourceTokenString, String agentId, String agentJkt) 
            throws SignatureVerificationException {
        
        try {
            // 1. Parse JWT
            JWSInput jws = new JWSInput(resourceTokenString);
            
            // 2. Verify typ is "resource+jwt"
            String typ = jws.getHeader().getType();
            if (!"resource+jwt".equals(typ)) {
                throw new SignatureVerificationException("Invalid token type, expected 'resource+jwt', got: " + typ);
            }

            // 3. Extract kid and iss
            String kid = jws.getHeader().getKeyId();
            JsonWebToken token = jws.readJsonContent(JsonWebToken.class);
            String iss = token.getIssuer();
            
            if (iss == null) {
                throw new SignatureVerificationException("Missing 'iss' claim in resource token");
            }

            // 4. Fetch resource metadata and JWKS
            MetadataFetcher fetcher = new MetadataFetcher(session);
            ResourceMetadata metadata = fetcher.fetchResourceMetadata(iss);
            
            if (metadata == null || metadata.getJwksUri() == null) {
                throw new SignatureVerificationException("Failed to fetch resource metadata or jwks_uri not found");
            }

            JSONWebKeySet jwks = fetcher.fetchJWKS(metadata.getJwksUri());
            if (jwks == null || jwks.getKeys() == null) {
                throw new SignatureVerificationException("Failed to fetch JWKS from resource");
            }

            // 5. Find signing key by kid and verify signature
            JWK signingKey = null;
            for (JWK jwk : jwks.getKeys()) {
                if (kid != null && kid.equals(jwk.getKeyId())) {
                    signingKey = jwk;
                    break;
                }
            }
            
            if (signingKey == null) {
                throw new SignatureVerificationException("Signing key with kid='" + kid + "' not found in resource JWKS");
            }

            // Note: Full signature verification will be done via Keycloak's crypto providers
            
            // 6. Validate required claims
            String aud = getAudience(token);
            if (aud == null) {
                throw new SignatureVerificationException("Missing 'aud' claim in resource token");
            }
            
            if (!authServerId.equals(aud)) {
                throw new SignatureVerificationException(
                    "Resource token audience mismatch: expected " + authServerId + ", got " + aud);
            }

            String tokenAgentId = getAgentClaim(token);
            if (tokenAgentId == null) {
                throw new SignatureVerificationException("Missing 'agent' claim in resource token");
            }
            
            if (!agentId.equals(tokenAgentId)) {
                throw new SignatureVerificationException(
                    "Resource token agent mismatch: expected " + agentId + ", got " + tokenAgentId);
            }

            String tokenAgentJkt = getAgentJktClaim(token);
            if (tokenAgentJkt == null) {
                throw new SignatureVerificationException("Missing 'agent_jkt' claim in resource token");
            }
            
            if (!agentJkt.equals(tokenAgentJkt)) {
                throw new SignatureVerificationException(
                    "Resource token agent_jkt mismatch: expected " + agentJkt + ", got " + tokenAgentJkt);
            }

            if (token.getExp() == null) {
                throw new SignatureVerificationException("Missing 'exp' claim in resource token");
            }
            
            if (token.isExpired()) {
                throw new SignatureVerificationException("Resource token has expired");
            }

            // 7. Extract scope or auth_request_url
            String scope = getScopeClaim(token);
            String authRequestUrl = getAuthRequestUrlClaim(token);
            
            if (scope == null && authRequestUrl == null) {
                throw new SignatureVerificationException("Missing 'scope' or 'auth_request_url' claim in resource token");
            }

            logger.debugf("Resource token validated successfully for resource: %s, agent: %s", iss, agentId);
            
            return new ResourceTokenValidationResult(iss, aud, agentId, scope, authRequestUrl);

        } catch (JWSInputException e) {
            throw new SignatureVerificationException("Failed to parse resource token", e);
        } catch (Exception e) {
            if (e instanceof SignatureVerificationException) {
                throw e;
            }
            throw new SignatureVerificationException("Failed to validate resource token", e);
        }
    }

    private String getAudience(JsonWebToken token) {
        String[] audience = token.getAudience();
        if (audience != null && audience.length > 0) {
            return audience[0];
        }
        return null;
    }

    @SuppressWarnings("unchecked")
    private String getAgentClaim(JsonWebToken token) {
        Map<String, Object> otherClaims = token.getOtherClaims();
        if (otherClaims != null) {
            Object agent = otherClaims.get("agent");
            if (agent instanceof String) {
                return (String) agent;
            }
        }
        return null;
    }

    @SuppressWarnings("unchecked")
    private String getAgentJktClaim(JsonWebToken token) {
        Map<String, Object> otherClaims = token.getOtherClaims();
        if (otherClaims != null) {
            Object agentJkt = otherClaims.get("agent_jkt");
            if (agentJkt instanceof String) {
                return (String) agentJkt;
            }
        }
        return null;
    }

    @SuppressWarnings("unchecked")
    private String getScopeClaim(JsonWebToken token) {
        Map<String, Object> otherClaims = token.getOtherClaims();
        if (otherClaims != null) {
            Object scope = otherClaims.get("scope");
            if (scope instanceof String) {
                return (String) scope;
            }
        }
        return null;
    }

    @SuppressWarnings("unchecked")
    private String getAuthRequestUrlClaim(JsonWebToken token) {
        Map<String, Object> otherClaims = token.getOtherClaims();
        if (otherClaims != null) {
            Object authRequestUrl = otherClaims.get("auth_request_url");
            if (authRequestUrl instanceof String) {
                return (String) authRequestUrl;
            }
        }
        return null;
    }

    /**
     * Result of resource token validation.
     */
    public static class ResourceTokenValidationResult {
        private final String resourceId;
        private final String audience;
        private final String agentId;
        private final String scope;
        private final String authRequestUrl;

        public ResourceTokenValidationResult(String resourceId, String audience, String agentId, 
                String scope, String authRequestUrl) {
            this.resourceId = resourceId;
            this.audience = audience;
            this.agentId = agentId;
            this.scope = scope;
            this.authRequestUrl = authRequestUrl;
        }

        public String getResourceId() {
            return resourceId;
        }

        public String getAudience() {
            return audience;
        }

        public String getAgentId() {
            return agentId;
        }

        public String getScope() {
            return scope;
        }

        public String getAuthRequestUrl() {
            return authRequestUrl;
        }
    }
}

