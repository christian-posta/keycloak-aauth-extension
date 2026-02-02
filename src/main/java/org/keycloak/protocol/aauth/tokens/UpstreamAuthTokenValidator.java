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
import org.keycloak.TokenVerifier;
import org.keycloak.common.VerificationException;
import org.keycloak.crypto.SignatureProvider;
import org.keycloak.crypto.SignatureVerifierContext;
import org.keycloak.jose.jws.JWSInput;
import org.keycloak.jose.jws.JWSInputException;
import org.keycloak.jose.jwk.JWK;
import org.keycloak.jose.jwk.JSONWebKeySet;
import org.keycloak.models.KeycloakSession;
import org.keycloak.models.RealmModel;
import org.keycloak.crypto.KeyWrapper;
import org.keycloak.protocol.aauth.federation.AuthServerTrustManager;
import org.keycloak.protocol.aauth.metadata.MetadataFetcher;
import org.keycloak.protocol.aauth.representations.AAuthIssuerMetadata;
import org.keycloak.protocol.aauth.util.AAuthJWKSUtils;
import org.keycloak.protocol.aauth.signing.exceptions.SignatureVerificationException;
import org.keycloak.protocol.aauth.representations.AAuthToken;
import org.keycloak.services.Urls;
import org.keycloak.util.JsonSerialization;

import java.util.Map;

/**
 * Validates upstream auth tokens from external AAuth auth servers.
 * 
 * Validates:
 * - JWT signature using upstream auth server's JWKS
 * - typ="auth+jwt"
 * - Required claims: iss, exp, cnf.jwk
 * - Optional claims: agent, sub, scope
 * - Issuer trust (via AuthServerTrustManager)
 * 
 * Used in token exchange flows to validate upstream tokens.
 */
public class UpstreamAuthTokenValidator {

    private static final Logger logger = Logger.getLogger(UpstreamAuthTokenValidator.class);
    
    private final KeycloakSession session;
    private final RealmModel realm;
    private final AuthServerTrustManager trustManager;
    private final String currentAuthServerId;

    public UpstreamAuthTokenValidator(KeycloakSession session, RealmModel realm) {
        this.session = session;
        this.realm = realm;
        this.trustManager = new AuthServerTrustManager(session, realm);
        // Get current auth server issuer for same-server exchange detection
        this.currentAuthServerId = Urls.realmIssuer(
                session.getContext().getUri().getBaseUri(), realm.getName());
    }

    /**
     * Validation result containing extracted claims from upstream token.
     */
    public static class UpstreamTokenValidationResult {
        private final AAuthToken token;
        private final String agentId;
        private final String agentDelegate;
        private final String sub;
        private final String scope;
        private final Map<String, Object> cnf;

        public UpstreamTokenValidationResult(AAuthToken token, String agentId, String agentDelegate, 
                String sub, String scope, Map<String, Object> cnf) {
            this.token = token;
            this.agentId = agentId;
            this.agentDelegate = agentDelegate;
            this.sub = sub;
            this.scope = scope;
            this.cnf = cnf;
        }

        public AAuthToken getToken() {
            return token;
        }

        public String getAgentId() {
            return agentId;
        }

        public String getAgentDelegate() {
            return agentDelegate;
        }

        public String getSub() {
            return sub;
        }

        public String getScope() {
            return scope;
        }

        public Map<String, Object> getCnf() {
            return cnf;
        }
    }

    /**
     * Validate an upstream auth token.
     * 
     * @param upstreamTokenString The upstream auth token JWT string
     * @return Validation result with extracted claims
     * @throws SignatureVerificationException If validation fails
     */
    public UpstreamTokenValidationResult validate(String upstreamTokenString) 
            throws SignatureVerificationException {
        
        try {
            // 1. Parse JWT
            JWSInput jws = new JWSInput(upstreamTokenString);
            
            // 2. Verify typ is "auth+jwt"
            String typ = jws.getHeader().getType();
            if (!"auth+jwt".equals(typ)) {
                throw new SignatureVerificationException("Invalid token type, expected 'auth+jwt', got: " + typ);
            }

            // 3. Extract issuer and kid
            String kid = jws.getHeader().getKeyId();
            AAuthToken token = jws.readJsonContent(AAuthToken.class);
            String iss = token.getIssuer();
            
            if (iss == null) {
                throw new SignatureVerificationException("Missing 'iss' claim in upstream auth token");
            }

            // 4. Check if this is same-server exchange or cross-server exchange
            boolean isSameServer = currentAuthServerId.equals(iss);
            
            if (isSameServer) {
                // Same-server exchange: Use current realm's keys directly
                logger.debugf("Same-server token exchange detected for issuer: %s", iss);
                // Trust is automatic for same-server
            } else {
                // Cross-server exchange: Verify issuer is trusted
                if (!trustManager.isTrusted(iss)) {
                    throw new SignatureVerificationException("Upstream auth server issuer is not trusted: " + iss);
                }
            }

            // 5. Get signing key and verify
            String algorithm = jws.getHeader().getRawAlgorithm();
            SignatureProvider signatureProvider = session.getProvider(SignatureProvider.class, algorithm);
            if (signatureProvider == null) {
                throw new SignatureVerificationException("Unsupported signature algorithm: " + algorithm);
            }

            SignatureVerifierContext verifierContext;
            if (isSameServer) {
                // Same-server exchange: Get key directly from Keycloak's key management
                // This avoids the JWK parsing issue with typed fields vs otherClaims
                KeyWrapper keyWrapper = session.keys().getKey(realm, kid, org.keycloak.crypto.KeyUse.SIG, algorithm);
                if (keyWrapper == null) {
                    throw new SignatureVerificationException("Signing key with kid='" + kid + "' not found in realm");
                }
                verifierContext = signatureProvider.verifier(keyWrapper);
            } else {
                // Cross-server exchange: Fetch upstream auth server metadata and JWKS
                String jwksUri = fetchUpstreamAuthServerJWKSUri(iss);
                if (jwksUri == null) {
                    throw new SignatureVerificationException("Failed to fetch upstream auth server metadata or jwks_uri not found for issuer: " + iss);
                }
                JSONWebKeySet jwks = fetchJWKS(jwksUri);
                if (jwks == null || jwks.getKeys() == null) {
                    throw new SignatureVerificationException("Failed to fetch JWKS from upstream auth server: " + iss);
                }

                // Find signing key by kid
                JWK signingKey = null;
                for (JWK jwk : jwks.getKeys()) {
                    if (kid != null && kid.equals(jwk.getKeyId())) {
                        signingKey = jwk;
                        break;
                    }
                }
                
                if (signingKey == null) {
                    throw new SignatureVerificationException("Signing key with kid='" + kid + "' not found in upstream auth server JWKS");
                }

                // Create KeyWrapper from JWK (cross-server JWKs come from JSON, so otherClaims works)
                KeyWrapper keyWrapper = org.keycloak.util.JWKSUtils.getKeyWrapper(signingKey);
                if (keyWrapper == null) {
                    throw new SignatureVerificationException("Failed to create key wrapper from JWK");
                }
                keyWrapper.setUse(org.keycloak.crypto.KeyUse.SIG);
                keyWrapper.setAlgorithm(algorithm);
                if (kid != null) {
                    keyWrapper.setKid(kid);
                }
                verifierContext = signatureProvider.verifier(keyWrapper);
            }

            if (verifierContext == null) {
                throw new SignatureVerificationException("Failed to create signature verifier for algorithm: " + algorithm);
            }

            // Verify signature and claims
            try {
                TokenVerifier<AAuthToken> verifier = TokenVerifier.create(upstreamTokenString, AAuthToken.class)
                        .withChecks(TokenVerifier.IS_ACTIVE)
                        .verifierContext(verifierContext);
                
                token = verifier.verify().getToken();
            } catch (VerificationException e) {
                throw new SignatureVerificationException("Upstream auth token signature verification failed: " + e.getMessage(), e);
            }

            // 8. Validate required claims
            if (token.getExp() == null) {
                throw new SignatureVerificationException("Missing 'exp' claim in upstream auth token");
            }
            
            if (token.isExpired()) {
                throw new SignatureVerificationException("Upstream auth token has expired");
            }

            // 9. Extract cnf claim
            Map<String, Object> cnf = extractCnfClaim(token);
            if (cnf == null || cnf.get("jwk") == null) {
                throw new SignatureVerificationException("Missing 'cnf.jwk' claim in upstream auth token");
            }

            // 10. Extract optional claims
            String agentId = token.getAgent();
            String agentDelegate = token.getAgentDelegate();
            String sub = token.getSubject();
            String scope = token.getScope();

            logger.debugf("Upstream auth token validated successfully for issuer: %s, agent: %s", iss, agentId);

            return new UpstreamTokenValidationResult(token, agentId, agentDelegate, sub, scope, cnf);

        } catch (JWSInputException e) {
            throw new SignatureVerificationException("Failed to parse upstream auth token", e);
        } catch (VerificationException e) {
            throw new SignatureVerificationException("Upstream auth token verification failed: " + e.getMessage(), e);
        } catch (SignatureVerificationException e) {
            throw e;
        } catch (Exception e) {
            throw new SignatureVerificationException("Failed to validate upstream auth token: " + e.getMessage(), e);
        }
    }

    /**
     * Fetch upstream auth server JWKS URI from metadata.
     */
    private String fetchUpstreamAuthServerJWKSUri(String issuer) {
        try {
            String wellKnownUrl = buildWellKnownUrl(issuer, "aauth-issuer");
            
            logger.debugf("Fetching upstream auth server metadata from: %s", wellKnownUrl);

            // Use HttpClientProvider directly since MetadataFetcher doesn't have a method for issuer metadata
            org.keycloak.connections.httpclient.HttpClientProvider httpClient = session.getProvider(org.keycloak.connections.httpclient.HttpClientProvider.class);
            String metadataJson = httpClient.getString(wellKnownUrl);

            if (metadataJson == null || metadataJson.trim().isEmpty()) {
                logger.warnf("Empty response from upstream auth server metadata endpoint: %s", wellKnownUrl);
                return null;
            }

            AAuthIssuerMetadata metadata = JsonSerialization.readValue(metadataJson, AAuthIssuerMetadata.class);
            
            // Validate that the issuer matches
            if (!issuer.equals(metadata.getIssuer())) {
                logger.warnf("Issuer mismatch: expected %s, got %s", issuer, metadata.getIssuer());
                return null;
            }

            return metadata.getJwksUri();

        } catch (Exception e) {
            logger.warnf(e, "Failed to fetch upstream auth server metadata from: %s", issuer);
            return null;
        }
    }

    /**
     * Fetch JWKS from a URI.
     */
    private JSONWebKeySet fetchJWKS(String jwksUri) {
        MetadataFetcher fetcher = new MetadataFetcher(session);
        return fetcher.fetchJWKS(jwksUri);
    }

    /**
     * Build a well-known URL from a base URL and document name.
     */
    private String buildWellKnownUrl(String baseUrl, String documentName) {
        // Ensure base URL doesn't end with /
        if (baseUrl.endsWith("/")) {
            baseUrl = baseUrl.substring(0, baseUrl.length() - 1);
        }
        return baseUrl + "/.well-known/" + documentName;
    }

    /**
     * Extract cnf claim from token.
     */
    @SuppressWarnings("unchecked")
    private Map<String, Object> extractCnfClaim(AAuthToken token) {
        if (token.getCnf() == null) {
            return null;
        }
        
        // Convert CnfClaim to Map
        Map<String, Object> cnf = new java.util.HashMap<>();
        if (token.getCnf().getJwk() != null) {
            try {
                // Serialize JWK to map
                String jwkJson = JsonSerialization.writeValueAsString(token.getCnf().getJwk());
                Map<String, Object> jwkMap = JsonSerialization.readValue(jwkJson, Map.class);
                cnf.put("jwk", jwkMap);
            } catch (Exception e) {
                logger.warnf(e, "Failed to serialize cnf.jwk claim");
                return null;
            }
        }
        
        return cnf;
    }
}

