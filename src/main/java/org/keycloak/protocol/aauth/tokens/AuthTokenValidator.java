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
import org.keycloak.connections.httpclient.HttpClientProvider;
import org.keycloak.crypto.KeyUse;
import org.keycloak.crypto.KeyWrapper;
import org.keycloak.crypto.SignatureProvider;
import org.keycloak.crypto.SignatureVerifierContext;
import org.keycloak.jose.jwk.JWK;
import org.keycloak.jose.jwk.JWKParser;
import org.keycloak.jose.jwk.JSONWebKeySet;
import org.keycloak.jose.jws.JWSInput;
import org.keycloak.jose.jws.JWSInputException;
import org.keycloak.models.KeycloakSession;
import org.keycloak.models.KeyManager;
import org.keycloak.protocol.aauth.signing.exceptions.SignatureVerificationException;
import org.keycloak.representations.JsonWebToken;
import org.keycloak.services.Urls;
import org.keycloak.util.JsonSerialization;

import java.util.Map;
import java.util.stream.Stream;

/**
 * Validates auth tokens (auth+jwt) per AAuth specification Section 7.7.
 * 
 * This validator performs full JWT signature verification against the issuer's JWKS.
 */
public class AuthTokenValidator {

    private static final Logger logger = Logger.getLogger(AuthTokenValidator.class);
    private final KeycloakSession session;

    public AuthTokenValidator(KeycloakSession session) {
        this.session = session;
    }

    /**
     * Validate auth token and extract cnf claim.
     * 
     * @param authTokenString The auth token JWT string
     * @return The cnf claim as a Map
     * @throws SignatureVerificationException If validation fails
     * @deprecated Use {@link #validateAuthToken(String)} for full validation with JWT signature verification
     */
    @Deprecated
    public Map<String, Object> validateAndExtractCnf(String authTokenString) throws SignatureVerificationException {
        AuthTokenValidationResult result = validateAuthToken(authTokenString);
        return result.getCnf();
    }

    /**
     * Validate auth token with full JWT signature verification.
     * 
     * This method:
     * 1. Parses the JWT
     * 2. Verifies typ is "auth+jwt"
     * 3. Verifies JWT signature against issuer's JWKS
     * 4. Validates expiration
     * 5. Extracts cnf claim
     * 
     * @param authTokenString The auth token JWT string
     * @return Validation result containing issuer, audience, agent, and cnf
     * @throws SignatureVerificationException If validation fails
     */
    @SuppressWarnings("unchecked")
    public AuthTokenValidationResult validateAuthToken(String authTokenString) throws SignatureVerificationException {
        try {
            // 1. Parse JWT
            JWSInput jws = new JWSInput(authTokenString);
            
            // 2. Verify typ is "auth+jwt"
            String typ = jws.getHeader().getType();
            if (!"auth+jwt".equals(typ)) {
                throw new SignatureVerificationException("Invalid token type, expected 'auth+jwt', got: " + typ);
            }

            // 3. Extract claims
            JsonWebToken token = jws.readJsonContent(JsonWebToken.class);
            String iss = token.getIssuer();
            
            if (iss == null) {
                throw new SignatureVerificationException("Missing 'iss' claim in auth token");
            }

            // 4. Verify JWT signature against issuer's JWKS
            verifyJwtSignature(jws, iss);

            // 5. Validate expiration
            if (token.getExp() == null) {
                throw new SignatureVerificationException("Missing 'exp' claim in auth token");
            }
            
            if (token.isExpired()) {
                throw new SignatureVerificationException("Auth token has expired");
            }

            // 6. Extract cnf claim
            Map<String, Object> otherClaims = token.getOtherClaims();
            if (otherClaims == null) {
                throw new SignatureVerificationException("Missing 'cnf' claim in auth token");
            }

            Object cnfObj = otherClaims.get("cnf");
            if (cnfObj == null) {
                throw new SignatureVerificationException("Missing 'cnf' claim in auth token");
            }

            if (!(cnfObj instanceof Map)) {
                throw new SignatureVerificationException("Invalid 'cnf' claim format in auth token");
            }

            Map<String, Object> cnf = (Map<String, Object>) cnfObj;
            
            // 7. Validate cnf.jwk exists
            Object jwkObj = cnf.get("jwk");
            if (jwkObj == null) {
                throw new SignatureVerificationException("Missing 'cnf.jwk' claim in auth token");
            }

            // 8. Extract audience
            String[] audience = token.getAudience();
            
            // 9. Extract agent claim
            String agentId = null;
            Object agentObj = otherClaims.get("agent");
            if (agentObj instanceof String) {
                agentId = (String) agentObj;
            }
            
            logger.debugf("Auth token validated successfully for issuer: %s", iss);
            
            return new AuthTokenValidationResult(iss, audience, agentId, cnf, authTokenString);

        } catch (JWSInputException e) {
            throw new SignatureVerificationException("Failed to parse auth token", e);
        } catch (Exception e) {
            if (e instanceof SignatureVerificationException) {
                throw e;
            }
            throw new SignatureVerificationException("Failed to validate auth token", e);
        }
    }

    /**
     * Verify JWT signature against the issuer's JWKS.
     */
    private void verifyJwtSignature(JWSInput jws, String issuer) throws SignatureVerificationException {
        String kid = jws.getHeader().getKeyId();
        String algorithm = jws.getHeader().getRawAlgorithm();
        
        logger.debugf("Verifying auth token JWT signature: issuer=%s, kid=%s, alg=%s", issuer, kid, algorithm);
        
        // Check if issuer is this Keycloak instance
        if (isLocalIssuer(issuer)) {
            verifyWithLocalKeys(jws, kid, algorithm);
        } else {
            verifyWithExternalJwks(jws, issuer, kid, algorithm);
        }
    }

    /**
     * Check if the issuer is this Keycloak instance.
     */
    private boolean isLocalIssuer(String issuer) {
        if (session == null || session.getContext() == null || session.getContext().getRealm() == null) {
            return false;
        }
        String localIssuer = Urls.realmIssuer(session.getContext().getUri().getBaseUri(), 
                                               session.getContext().getRealm().getName());
        return issuer.equals(localIssuer);
    }

    /**
     * Verify JWT signature using local Keycloak keys.
     */
    private void verifyWithLocalKeys(JWSInput jws, String kid, String algorithm) throws SignatureVerificationException {
        try {
            KeyManager keyManager = session.keys();
            
            // Normalize algorithm for Keycloak's signature providers
            String normalizedAlg = normalizeAlgorithm(algorithm);
            
            // Get keys that can verify this algorithm
            Stream<KeyWrapper> keys = keyManager.getKeysStream(session.getContext().getRealm())
                    .filter(k -> k.getStatus().isEnabled())
                    .filter(k -> KeyUse.SIG.equals(k.getUse()))
                    .filter(k -> normalizedAlg.equals(k.getAlgorithm()));
            
            // If kid is specified, filter by it
            if (kid != null) {
                keys = keys.filter(k -> kid.equals(k.getKid()));
            }
            
            KeyWrapper key = keys.findFirst().orElse(null);
            
            if (key == null) {
                throw new SignatureVerificationException("No suitable key found for auth token verification: kid=" + kid + ", alg=" + algorithm);
            }
            
            SignatureProvider signatureProvider = session.getProvider(SignatureProvider.class, normalizedAlg);
            if (signatureProvider == null) {
                throw new SignatureVerificationException("Unsupported signature algorithm: " + algorithm);
            }
            
            SignatureVerifierContext verifier = signatureProvider.verifier(key);
            if (!verifier.verify(jws.getEncodedSignatureInput().getBytes("UTF-8"), jws.getSignature())) {
                throw new SignatureVerificationException("Auth token JWT signature verification failed");
            }
            
            logger.debug("Auth token JWT signature verified using local keys");
            
        } catch (SignatureVerificationException e) {
            throw e;
        } catch (Exception e) {
            throw new SignatureVerificationException("Failed to verify auth token JWT signature", e);
        }
    }

    /**
     * Normalize algorithm name for Keycloak's signature providers.
     * EdDSA in JWT header maps to Ed25519 in Keycloak.
     */
    private String normalizeAlgorithm(String algorithm) {
        if ("EdDSA".equals(algorithm)) {
            return "Ed25519";
        }
        return algorithm;
    }

    /**
     * Verify JWT signature using external issuer's JWKS.
     */
    private void verifyWithExternalJwks(JWSInput jws, String issuer, String kid, String algorithm) 
            throws SignatureVerificationException {
        try {
            // Fetch JWKS from issuer's OIDC discovery endpoint
            String jwksUri = issuer + "/protocol/openid-connect/certs";
            logger.debugf("Fetching external JWKS from: %s", jwksUri);
            
            HttpClientProvider httpClient = session.getProvider(HttpClientProvider.class);
            String jwksJson = httpClient.getString(jwksUri);
            
            if (jwksJson == null || jwksJson.trim().isEmpty()) {
                throw new SignatureVerificationException("Failed to fetch JWKS from issuer: " + issuer);
            }
            
            JSONWebKeySet jwks = JsonSerialization.readValue(jwksJson, JSONWebKeySet.class);
            if (jwks == null || jwks.getKeys() == null || jwks.getKeys().length == 0) {
                throw new SignatureVerificationException("No keys in JWKS from issuer: " + issuer);
            }
            
            // Find the signing key
            JWK signingKey = null;
            for (JWK jwk : jwks.getKeys()) {
                if (kid != null && kid.equals(jwk.getKeyId())) {
                    signingKey = jwk;
                    break;
                }
            }
            
            // If kid not found, try to use the first key with matching algorithm
            if (signingKey == null && kid == null) {
                for (JWK jwk : jwks.getKeys()) {
                    if (algorithm.equals(jwk.getAlgorithm()) || 
                        (algorithm.equals("EdDSA") && "OKP".equals(jwk.getKeyType()))) {
                        signingKey = jwk;
                        break;
                    }
                }
            }
            
            if (signingKey == null) {
                throw new SignatureVerificationException("Signing key not found in issuer JWKS: kid=" + kid);
            }
            
            // Verify signature
            java.security.PublicKey publicKey = JWKParser.create(signingKey).toPublicKey();
            KeyWrapper keyWrapper = new KeyWrapper();
            keyWrapper.setPublicKey(publicKey);
            
            // Normalize algorithm for Keycloak's signature providers
            String normalizedAlg = normalizeAlgorithm(algorithm);
            keyWrapper.setAlgorithm(normalizedAlg);
            
            if ("Ed25519".equals(normalizedAlg) || "EdDSA".equals(algorithm)) {
                keyWrapper.setCurve("Ed25519");
            }
            
            SignatureProvider signatureProvider = session.getProvider(SignatureProvider.class, normalizedAlg);
            if (signatureProvider == null) {
                throw new SignatureVerificationException("Unsupported signature algorithm: " + algorithm);
            }
            
            SignatureVerifierContext verifier = signatureProvider.verifier(keyWrapper);
            if (!verifier.verify(jws.getEncodedSignatureInput().getBytes("UTF-8"), jws.getSignature())) {
                throw new SignatureVerificationException("Auth token JWT signature verification failed against external JWKS");
            }
            
            logger.debug("Auth token JWT signature verified using external JWKS");
            
        } catch (SignatureVerificationException e) {
            throw e;
        } catch (Exception e) {
            throw new SignatureVerificationException("Failed to verify auth token JWT signature against external JWKS", e);
        }
    }

    /**
     * Result of auth token validation.
     */
    public static class AuthTokenValidationResult {
        private final String issuer;
        private final String[] audience;
        private final String agentId;
        private final Map<String, Object> cnf;
        private final String tokenString;

        public AuthTokenValidationResult(String issuer, String[] audience, String agentId, 
                Map<String, Object> cnf, String tokenString) {
            this.issuer = issuer;
            this.audience = audience;
            this.agentId = agentId;
            this.cnf = cnf;
            this.tokenString = tokenString;
        }

        public String getIssuer() {
            return issuer;
        }

        public String[] getAudience() {
            return audience;
        }

        public String getAgentId() {
            return agentId;
        }

        public Map<String, Object> getCnf() {
            return cnf;
        }

        public String getTokenString() {
            return tokenString;
        }
    }
}

