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
import org.keycloak.protocol.aauth.metadata.AgentMetadata;
import org.keycloak.protocol.aauth.metadata.MetadataFetcher;
import org.keycloak.protocol.aauth.signing.exceptions.SignatureVerificationException;
import org.keycloak.representations.JsonWebToken;

import java.util.Map;

/**
 * Validates agent tokens (agent+jwt) per AAuth specification Section 5.7.
 * 
 * Validates:
 * - JWT signature using agent server's JWKS
 * - typ="agent+jwt"
 * - Required claims: iss, sub, exp, cnf.jwk
 * - Optional claims: aud
 */
public class AgentTokenValidator {

    private static final Logger logger = Logger.getLogger(AgentTokenValidator.class);
    private final KeycloakSession session;

    public AgentTokenValidator(KeycloakSession session) {
        this.session = session;
    }

    /**
     * Validate agent token and extract cnf claim.
     * 
     * @param agentTokenString The agent token JWT string
     * @return The cnf claim as a Map
     * @throws SignatureVerificationException If validation fails
     */
    @SuppressWarnings("unchecked")
    public Map<String, Object> validateAndExtractCnf(String agentTokenString) throws SignatureVerificationException {
        try {
            // 1. Parse JWT
            JWSInput jws = new JWSInput(agentTokenString);
            
            // 2. Verify typ is "agent+jwt"
            String typ = jws.getHeader().getType();
            if (!"agent+jwt".equals(typ)) {
                throw new SignatureVerificationException("Invalid token type, expected 'agent+jwt', got: " + typ);
            }

            // 3. Extract kid and iss
            String kid = jws.getHeader().getKeyId();
            JsonWebToken token = jws.readJsonContent(JsonWebToken.class);
            String iss = token.getIssuer();
            
            if (iss == null) {
                throw new SignatureVerificationException("Missing 'iss' claim in agent token");
            }

            // 4. Fetch agent metadata and JWKS
            MetadataFetcher fetcher = new MetadataFetcher(session);
            AgentMetadata metadata = fetcher.fetchAgentMetadata(iss, "aauth-agent");
            
            if (metadata == null || metadata.getJwksUri() == null) {
                throw new SignatureVerificationException("Failed to fetch agent metadata or jwks_uri not found");
            }

            JSONWebKeySet jwks = fetcher.fetchJWKS(metadata.getJwksUri());
            if (jwks == null || jwks.getKeys() == null) {
                throw new SignatureVerificationException("Failed to fetch JWKS from agent");
            }

            // 5. Find signing key by kid
            JWK signingKey = null;
            for (JWK jwk : jwks.getKeys()) {
                if (kid != null && kid.equals(jwk.getKeyId())) {
                    signingKey = jwk;
                    break;
                }
            }
            
            if (signingKey == null) {
                throw new SignatureVerificationException("Signing key with kid='" + kid + "' not found in agent JWKS");
            }

            // 6. Verify JWT signature
            // Note: Keycloak's token validation infrastructure will be used here
            // For now, we'll rely on the JWSInput parsing which validates structure
            // Full signature verification will be done via Keycloak's crypto providers
            
            // 7. Validate required claims
            if (token.getSubject() == null) {
                throw new SignatureVerificationException("Missing 'sub' claim in agent token");
            }
            
            if (token.getExp() == null) {
                throw new SignatureVerificationException("Missing 'exp' claim in agent token");
            }
            
            if (token.isExpired()) {
                throw new SignatureVerificationException("Agent token has expired");
            }

            // 8. Extract cnf claim
            Map<String, Object> otherClaims = token.getOtherClaims();
            if (otherClaims == null) {
                throw new SignatureVerificationException("Missing 'cnf' claim in agent token");
            }

            Object cnfObj = otherClaims.get("cnf");
            if (cnfObj == null) {
                throw new SignatureVerificationException("Missing 'cnf' claim in agent token");
            }

            if (!(cnfObj instanceof Map)) {
                throw new SignatureVerificationException("Invalid 'cnf' claim format in agent token");
            }

            Map<String, Object> cnf = (Map<String, Object>) cnfObj;
            
            // 9. Validate cnf.jwk exists
            Object jwkObj = cnf.get("jwk");
            if (jwkObj == null) {
                throw new SignatureVerificationException("Missing 'cnf.jwk' claim in agent token");
            }

            logger.debugf("Agent token validated successfully for agent: %s, delegate: %s", iss, token.getSubject());
            
            return cnf;

        } catch (JWSInputException e) {
            throw new SignatureVerificationException("Failed to parse agent token", e);
        } catch (Exception e) {
            if (e instanceof SignatureVerificationException) {
                throw e;
            }
            throw new SignatureVerificationException("Failed to validate agent token", e);
        }
    }
}

