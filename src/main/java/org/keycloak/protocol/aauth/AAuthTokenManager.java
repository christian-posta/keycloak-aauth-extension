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

package org.keycloak.protocol.aauth;

import org.jboss.logging.Logger;
import org.keycloak.common.util.Time;
import org.keycloak.crypto.KeyUse;
import org.keycloak.crypto.KeyWrapper;
import org.keycloak.crypto.SignatureProvider;
import org.keycloak.crypto.SignatureSignerContext;
import org.keycloak.jose.jwk.JWK;
import org.keycloak.jose.jwk.JWKBuilder;
import org.keycloak.jose.jws.JWSBuilder;
import org.keycloak.TokenVerifier;
import org.keycloak.common.VerificationException;
import org.keycloak.crypto.SignatureVerifierContext;
import org.keycloak.jose.jws.JWSInput;
import org.keycloak.jose.jws.JWSInputException;
import org.keycloak.models.KeycloakSession;
import org.keycloak.models.RealmModel;
import org.keycloak.models.UserModel;
import org.keycloak.models.UserSessionModel;
import org.keycloak.protocol.aauth.representations.AAuthActorClaim;
import org.keycloak.protocol.aauth.representations.AAuthRefreshToken;
import org.keycloak.protocol.aauth.representations.AAuthToken;
import org.keycloak.protocol.aauth.util.AAuthJWKSUtils;
import org.keycloak.services.Urls;

import java.security.PublicKey;
import java.util.Map;

/**
 * Token manager for creating AAuth tokens.
 * 
 * Creates auth tokens with typ="auth+jwt" header and AAuth-specific claims.
 */
public class AAuthTokenManager {

    private static final Logger logger = Logger.getLogger(AAuthTokenManager.class);

    private final KeycloakSession session;

    public AAuthTokenManager(KeycloakSession session) {
        this.session = session;
    }

    /**
     * Create an auth token for the given agent and resource.
     * 
     * @param realm The realm
     * @param agentId Agent HTTPS URL
     * @param agentDelegate Agent delegate identifier (optional)
     * @param agentPublicKey Agent's public signing key (for cnf.jwk)
     * @param resourceId Resource identifier (aud claim)
     * @param scope Space-separated scopes (optional)
     * @param user User model (optional, for user authorization)
     * @return Signed auth token JWT string
     */
    public String createAuthToken(RealmModel realm, String agentId, String agentDelegate,
            PublicKey agentPublicKey, String resourceId, String scope, UserModel user) {
        
        // Create AAuthToken instance
        AAuthToken token = new AAuthToken();
        
        // Set issuer
        String issuer = Urls.realmIssuer(session.getContext().getUri().getBaseUri(), realm.getName());
        token.issuer(issuer);
        
        // Set audience (resource identifier)
        token.audience(resourceId);
        
        // Set agent claim (if different from aud)
        if (!resourceId.equals(agentId)) {
            token.agent(agentId);
        }
        
        // Set agent_delegate if present
        if (agentDelegate != null) {
            token.agentDelegate(agentDelegate);
        }
        
        // Set scope if provided
        if (scope != null && !scope.trim().isEmpty()) {
            token.setScope(scope);
        }
        
        // Set user claims if user provided
        if (user != null) {
            token.subject(user.getId());
            // Additional user claims can be added here if needed
        }
        
        // Set expiration (use realm's access token lifespan)
        int tokenLifespan = realm.getAccessTokenLifespan();
        if (tokenLifespan == -1) {
            tokenLifespan = 300; // Default 5 minutes if not configured
        }
        long expiration = Time.currentTime() + tokenLifespan;
        token.exp(expiration);
        
        // Set issued at
        token.issuedNow();
        
        // Convert agent's public key to JWK for cnf.jwk
        JWK agentJwk = convertPublicKeyToJWK(agentPublicKey);
        token.setCnfJwk(agentJwk);
        
        // Get realm signing key and algorithm
        String signingAlgorithm = session.tokens().signatureAlgorithm(org.keycloak.TokenCategory.ACCESS);
        KeyWrapper signingKey = session.keys().getActiveKey(realm, KeyUse.SIG, signingAlgorithm);
        
        if (signingKey == null) {
            throw new RuntimeException("Active signing key not found for algorithm: " + signingAlgorithm);
        }
        
        // Create signer context
        SignatureProvider signatureProvider = session.getProvider(SignatureProvider.class, signingAlgorithm);
        SignatureSignerContext signer = signatureProvider.signer(signingKey);
        
        // Build and sign JWT with typ="auth+jwt"
        String signedToken = new JWSBuilder()
                .type("auth+jwt")
                .kid(signingKey.getKid())
                .jsonContent(token)
                .sign(signer);
        
        logger.debugf("Created auth token for agent: %s, resource: %s", agentId, resourceId);
        
        return signedToken;
    }

    /**
     * Convert PublicKey to JWK for cnf.jwk claim.
     */
    private JWK convertPublicKeyToJWK(PublicKey publicKey) {
        String algorithm = publicKey.getAlgorithm();
        
        if ("EdDSA".equals(algorithm) || publicKey instanceof java.security.interfaces.EdECPublicKey) {
            // Ed25519 or Ed448
            return JWKBuilder.create().okp(publicKey);
        } else if ("RSA".equals(algorithm) || publicKey instanceof java.security.interfaces.RSAPublicKey) {
            return JWKBuilder.create().rsa(publicKey, null, null);
        } else if ("EC".equals(algorithm) || publicKey instanceof java.security.interfaces.ECPublicKey) {
            return JWKBuilder.create().ec(publicKey, null, null);
        } else {
            throw new RuntimeException("Unsupported public key type: " + algorithm);
        }
    }

    /**
     * Calculate JWK thumbprint (agent_jkt) from PublicKey.
     */
    public String calculateAgentJkt(PublicKey agentPublicKey) {
        JWK agentJwk = convertPublicKeyToJWK(agentPublicKey);
        return AAuthJWKSUtils.computeThumbprint(agentJwk);
    }

    /**
     * Get token expiration in seconds.
     */
    public long getTokenExpiration(RealmModel realm) {
        int tokenLifespan = realm.getAccessTokenLifespan();
        if (tokenLifespan == -1) {
            return 300; // Default 5 minutes
        }
        return tokenLifespan;
    }

    /**
     * Create a refresh token for the given agent and resource.
     * 
     * @param realm The realm
     * @param agentId Agent identifier (HTTPS URL or pseudonymous)
     * @param agentJkt Agent JWK thumbprint
     * @param agentDelegate Agent delegate identifier (optional)
     * @param resourceId Resource identifier
     * @param scope Space-separated scopes (optional)
     * @param user User model (optional, for user authorization)
     * @param agentPublicKey Agent's public signing key (for cnf.jwk)
     * @return Signed refresh token JWT string
     */
    public String createRefreshToken(RealmModel realm, String agentId, String agentJkt, 
            String agentDelegate, String resourceId, String scope, UserModel user, 
            PublicKey agentPublicKey) {
        
        // Create AAuthRefreshToken instance
        AAuthRefreshToken refreshToken = new AAuthRefreshToken();
        
        // Set issuer
        String issuer = Urls.realmIssuer(session.getContext().getUri().getBaseUri(), realm.getName());
        refreshToken.issuer(issuer);
        
        // Set audience (resource identifier)
        refreshToken.audience(new String[] { issuer }); // Refresh tokens have issuer as audience
        
        // Set agent binding fields
        refreshToken.agent(agentId);
        refreshToken.agentJkt(agentJkt);
        
        if (agentDelegate != null) {
            refreshToken.agentDelegate(agentDelegate);
        }
        
        refreshToken.resourceId(resourceId);
        
        // Set scope if provided
        if (scope != null && !scope.trim().isEmpty()) {
            refreshToken.setScope(scope);
        }
        
        // Set user claims if user provided
        if (user != null) {
            refreshToken.subject(user.getId());
        }
        
        // Set expiration (use realm's refresh token lifespan, or default to 30 days)
        int refreshTokenLifespan = realm.getSsoSessionMaxLifespan();
        if (refreshTokenLifespan == -1) {
            refreshTokenLifespan = 2592000; // Default 30 days
        }
        long expiration = Time.currentTime() + refreshTokenLifespan;
        refreshToken.exp(expiration);
        
        // Set issued at
        refreshToken.issuedNow();
        
        // Generate token ID
        refreshToken.id(org.keycloak.models.utils.KeycloakModelUtils.generateId());
        
        // Convert agent's public key to JWK for cnf.jwk
        JWK agentJwk = convertPublicKeyToJWK(agentPublicKey);
        refreshToken.setCnfJwk(agentJwk);
        
        // Get realm signing key and algorithm
        // Use ACCESS category (same as access tokens) instead of INTERNAL to avoid HMAC
        String signingAlgorithm = session.tokens().signatureAlgorithm(org.keycloak.TokenCategory.ACCESS);
        KeyWrapper signingKey = session.keys().getActiveKey(realm, KeyUse.SIG, signingAlgorithm);
        
        if (signingKey == null) {
            throw new RuntimeException("Active signing key not found for algorithm: " + signingAlgorithm);
        }
        
        // Create signer context
        SignatureProvider signatureProvider = session.getProvider(SignatureProvider.class, signingAlgorithm);
        SignatureSignerContext signer = signatureProvider.signer(signingKey);
        
        // Build and sign JWT with typ="refresh+jwt"
        String signedToken = new JWSBuilder()
                .type("refresh+jwt")
                .kid(signingKey.getKid())
                .jsonContent(refreshToken)
                .sign(signer);
        
        logger.debugf("Created refresh token for agent: %s, resource: %s", agentId, resourceId);
        
        return signedToken;
    }

    /**
     * Validate and parse a refresh token.
     * 
     * @param realm The realm
     * @param encodedRefreshToken Encoded refresh token JWT string
     * @return Parsed and validated refresh token
     * @throws VerificationException If token is invalid
     */
    public AAuthRefreshToken validateRefreshToken(RealmModel realm, String encodedRefreshToken) 
            throws VerificationException {
        
        try {
            // Parse JWT
            JWSInput jwsInput = new JWSInput(encodedRefreshToken);
            
            // Verify token type
            if (!"refresh+jwt".equals(jwsInput.getHeader().getType())) {
                throw new VerificationException("Invalid refresh token type");
            }
            
            // Get algorithm and key ID from token header
            String algorithm = jwsInput.getHeader().getAlgorithm().name();
            String kid = jwsInput.getHeader().getKeyId();
            
            // Get signature verifier context from realm keys
            SignatureProvider signatureProvider = session.getProvider(SignatureProvider.class, algorithm);
            if (signatureProvider == null) {
                throw new VerificationException("Unsupported signature algorithm: " + algorithm);
            }
            
            SignatureVerifierContext verifierContext = signatureProvider.verifier(kid);
            
            // Verify signature and claims
            String issuer = Urls.realmIssuer(session.getContext().getUri().getBaseUri(), realm.getName());
            TokenVerifier<AAuthRefreshToken> verifier = TokenVerifier.create(encodedRefreshToken, AAuthRefreshToken.class)
                    .withChecks(
                            TokenVerifier.IS_ACTIVE,
                            new TokenVerifier.RealmUrlCheck(issuer)
                    )
                    .verifierContext(verifierContext);
            
            AAuthRefreshToken refreshToken = verifier.verify().getToken();
            
            return refreshToken;
            
        } catch (JWSInputException e) {
            throw new VerificationException("Invalid refresh token format", e);
        }
    }

    /**
     * Generate a new auth token from a refresh token.
     * 
     * @param realm The realm
     * @param refreshToken Validated refresh token
     * @param agentPublicKey Current agent's public key (for cnf.jwk in new token)
     * @return New signed auth token JWT string
     */
    public String refreshAuthToken(RealmModel realm, AAuthRefreshToken refreshToken, 
            PublicKey agentPublicKey) {
        
        // Get user session if subject is present
        UserModel user = null;
        if (refreshToken.getSubject() != null && refreshToken.getSessionId() != null) {
            UserSessionModel userSession = session.sessions().getUserSession(realm, refreshToken.getSessionId());
            if (userSession != null) {
                user = userSession.getUser();
            }
        }
        
        // Create new auth token with same parameters as refresh token
        String agentId = refreshToken.getAgent();
        String agentDelegate = refreshToken.getAgentDelegate();
        String resourceId = refreshToken.getResourceId();
        String scope = refreshToken.getScope();
        
        return createAuthToken(realm, agentId, agentDelegate, agentPublicKey, resourceId, scope, user);
    }

    /**
     * Create an auth token with an actor claim for token exchange scenarios.
     * 
     * @param realm The realm
     * @param agentId Agent HTTPS URL (current agent making the exchange request)
     * @param agentDelegate Agent delegate identifier (optional)
     * @param agentPublicKey Agent's public signing key (for cnf.jwk)
     * @param resourceId Resource identifier (aud claim)
     * @param scope Space-separated scopes (optional, must be narrowed from upstream scope)
     * @param user User model (optional, for user authorization)
     * @param actorClaim Actor claim representing the upstream agent delegation chain
     * @return Signed auth token JWT string with act claim
     */
    public String createAuthTokenWithActor(RealmModel realm, String agentId, String agentDelegate,
            PublicKey agentPublicKey, String resourceId, String scope, UserModel user,
            AAuthActorClaim actorClaim) {
        
        // Create AAuthToken instance
        AAuthToken token = new AAuthToken();
        
        // Set issuer
        String issuer = Urls.realmIssuer(session.getContext().getUri().getBaseUri(), realm.getName());
        token.issuer(issuer);
        
        // Set audience (resource identifier)
        token.audience(resourceId);
        
        // Set agent claim (current agent making the exchange request)
        token.agent(agentId);
        
        // Set agent_delegate if present
        if (agentDelegate != null) {
            token.agentDelegate(agentDelegate);
        }
        
        // Set scope if provided
        if (scope != null && !scope.trim().isEmpty()) {
            token.setScope(scope);
        }
        
        // Set user claims if user provided
        // If upstream token had a user, preserve it through the delegation chain
        if (user != null) {
            token.subject(user.getId());
        } else if (actorClaim != null && actorClaim.getSub() != null) {
            // Preserve upstream user subject if present
            token.subject(actorClaim.getSub());
        }
        
        // Set expiration (use realm's access token lifespan)
        int tokenLifespan = realm.getAccessTokenLifespan();
        if (tokenLifespan == -1) {
            tokenLifespan = 300; // Default 5 minutes if not configured
        }
        long expiration = Time.currentTime() + tokenLifespan;
        token.exp(expiration);
        
        // Set issued at
        token.issuedNow();
        
        // Convert agent's public key to JWK for cnf.jwk
        JWK agentJwk = convertPublicKeyToJWK(agentPublicKey);
        token.setCnfJwk(agentJwk);
        
        // Set actor claim (convert to Map for JWT)
        if (actorClaim != null) {
            Map<String, Object> actMap = actorClaim.toMap();
            token.setAct(actMap);
        }
        
        // Get realm signing key and algorithm
        String signingAlgorithm = session.tokens().signatureAlgorithm(org.keycloak.TokenCategory.ACCESS);
        KeyWrapper signingKey = session.keys().getActiveKey(realm, KeyUse.SIG, signingAlgorithm);
        
        if (signingKey == null) {
            throw new RuntimeException("Active signing key not found for algorithm: " + signingAlgorithm);
        }
        
        // Create signer context
        SignatureProvider signatureProvider = session.getProvider(SignatureProvider.class, signingAlgorithm);
        SignatureSignerContext signer = signatureProvider.signer(signingKey);
        
        // Build and sign JWT with typ="auth+jwt"
        String signedToken = new JWSBuilder()
                .type("auth+jwt")
                .kid(signingKey.getKid())
                .jsonContent(token)
                .sign(signer);
        
        logger.debugf("Created auth token with actor claim for agent: %s, resource: %s, upstream agent: %s", 
                agentId, resourceId, actorClaim != null ? actorClaim.getAgent() : "N/A");
        
        return signedToken;
    }
}

