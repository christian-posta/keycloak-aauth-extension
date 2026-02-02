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

package org.keycloak.protocol.aauth.grants;

import org.jboss.logging.Logger;
import org.keycloak.OAuthErrorException;
import org.keycloak.events.EventType;
import org.keycloak.models.KeycloakSession;
import org.keycloak.models.RealmModel;
import org.keycloak.protocol.aauth.AAuthTokenManager;
import org.keycloak.protocol.aauth.policy.AAuthPolicyEvaluator;
import org.keycloak.protocol.aauth.policy.DefaultAAuthPolicyEvaluator;
import org.keycloak.protocol.aauth.storage.AAuthRequestTokenStore;
import org.keycloak.protocol.aauth.tokens.ResourceTokenValidator;
import org.keycloak.protocol.oidc.grants.OAuth2GrantType;
import org.keycloak.protocol.aauth.representations.AAuthTokenResponse;
import org.keycloak.services.CorsErrorResponseException;
import org.keycloak.services.Urls;
import org.keycloak.services.cors.Cors;

import jakarta.ws.rs.core.MediaType;
import jakarta.ws.rs.core.Response;

import java.security.PublicKey;
import java.util.Collections;
import java.util.Set;

/**
 * Auth grant type for AAuth protocol (request_type=auth).
 * 
 * Implements direct grant flow for machine-to-machine scenarios without user consent.
 * Validates resource_token or scope, then issues auth_token.
 */
public class AuthGrantType implements OAuth2GrantType {

    private static final Logger logger = Logger.getLogger(AuthGrantType.class);

    @Override
    public EventType getEventType() {
        return EventType.CLIENT_LOGIN; // Machine-to-machine flow similar to client credentials
    }

    @Override
    public Set<String> getSupportedMultivaluedRequestParameters() {
        return Collections.emptySet();
    }

    @Override
    public Response process(Context context) {
        KeycloakSession session = context.getSession();
        RealmModel realm = context.getRealm();
        Cors cors = context.getCors();

        // Extract agent identity from session (set by AAuthSignatureFilter)
        String agentId = (String) session.getAttribute("aauth.agent.id");
        PublicKey agentPublicKey = (PublicKey) session.getAttribute("aauth.agent.public.key");
        String signatureScheme = (String) session.getAttribute("aauth.signature.scheme");

        if (agentPublicKey == null) {
            throw new CorsErrorResponseException(cors, OAuthErrorException.INVALID_REQUEST,
                    "Agent identity not found. Request must be signed with HTTPSig.", Response.Status.UNAUTHORIZED);
        }

        // For pseudonymous schemes (hwk), agentId may be null
        // In this case, derive a pseudonymous identifier from the public key thumbprint
        if (agentId == null && "hwk".equals(signatureScheme)) {
            AAuthTokenManager tokenManager = new AAuthTokenManager(session);
            String agentJkt = tokenManager.calculateAgentJkt(agentPublicKey);
            // Use JKT as pseudonymous agent identifier for hwk scheme
            agentId = "pseudonymous:" + agentJkt;
        } else if (agentId == null) {
            // For other schemes, agentId should be present
            throw new CorsErrorResponseException(cors, OAuthErrorException.INVALID_REQUEST,
                    "Agent identity not found. Request must be signed with HTTPSig.", Response.Status.UNAUTHORIZED);
        }

        return processGrant(session, realm, cors, agentId, agentPublicKey, signatureScheme, context);
    }

    private Response processGrant(KeycloakSession session, RealmModel realm, Cors cors,
            String agentId, PublicKey agentPublicKey, String signatureScheme, Context context) {
        
        // Policy checks
        AAuthPolicyEvaluator policyEvaluator = DefaultAAuthPolicyEvaluator.create(session);
        
        // Check if AAuth is enabled for this realm
        if (!policyEvaluator.isProtocolEnabled(realm)) {
            throw new CorsErrorResponseException(cors, OAuthErrorException.INVALID_REQUEST,
                    "AAuth protocol is not enabled for this realm", Response.Status.BAD_REQUEST);
        }
        
        // Check if agent is allowed
        if (!policyEvaluator.isAgentAllowed(agentId, realm)) {
            throw new CorsErrorResponseException(cors, OAuthErrorException.ACCESS_DENIED,
                    "Agent is not allowed by policy", Response.Status.FORBIDDEN);
        }
        
        String resourceToken = context.getFormParams().getFirst("resource_token");
        String scope = context.getFormParams().getFirst("scope");
        String authRequestUrl = context.getFormParams().getFirst("auth_request_url");
        String redirectUri = context.getFormParams().getFirst("redirect_uri");
        String state = context.getFormParams().getFirst("state");
        
        // Check if requested scopes are allowed
        if (scope != null && !policyEvaluator.areScopesAllowed(scope, realm)) {
            throw new CorsErrorResponseException(cors, OAuthErrorException.INVALID_SCOPE,
                    "One or more requested scopes are not allowed", Response.Status.BAD_REQUEST);
        }

        String resourceId;
        String grantedScope = null;
        String agentDelegate = null;

        if (resourceToken != null) {
            // Validate resource token
            String authServerId = Urls.realmIssuer(session.getContext().getUri().getBaseUri(), realm.getName());
            ResourceTokenValidator validator = new ResourceTokenValidator(session, authServerId);
            
            AAuthTokenManager tokenManager = new AAuthTokenManager(session);
            String agentJkt = tokenManager.calculateAgentJkt(agentPublicKey);
            
            try {
                ResourceTokenValidator.ResourceTokenValidationResult result = 
                        validator.validate(resourceToken, agentId, agentJkt);
                
                resourceId = result.getResourceId();
                grantedScope = result.getScope();
                // Note: auth_request_url could also be extracted from result if needed
                
            } catch (org.keycloak.protocol.aauth.signing.exceptions.SignatureVerificationException e) {
                logger.warnf(e, "Resource token validation failed for agent: %s", agentId);
                throw new CorsErrorResponseException(cors, OAuthErrorException.INVALID_GRANT,
                        "Invalid resource_token: " + e.getMessage(), Response.Status.BAD_REQUEST);
            }
            
        } else if (scope != null || authRequestUrl != null) {
            // Agent is acting as resource (self-authorization)
            resourceId = agentId;
            grantedScope = scope;
            
        } else {
            throw new CorsErrorResponseException(cors, OAuthErrorException.INVALID_REQUEST,
                    "Missing required parameter: resource_token or scope", Response.Status.BAD_REQUEST);
        }

        // Evaluate authorization policy - determine if user consent is required
        boolean requiresConsent = requiresUserConsent(realm, grantedScope, resourceId);
        
        if (requiresConsent) {
            // User consent required - issue request_token
            if (redirectUri == null || redirectUri.isEmpty()) {
                throw new CorsErrorResponseException(cors, OAuthErrorException.INVALID_REQUEST,
                        "redirect_uri is required when user consent is needed", Response.Status.BAD_REQUEST);
            }
            
            AAuthTokenManager tokenManager = new AAuthTokenManager(session);
            String agentJkt = tokenManager.calculateAgentJkt(agentPublicKey);
            
            AAuthRequestTokenStore tokenStore = new AAuthRequestTokenStore(session);
            String requestToken = tokenStore.createRequestToken(
                    agentId, agentJkt, signatureScheme, resourceId, grantedScope,
                    authRequestUrl, redirectUri, state);
            
            AAuthTokenResponse response = new AAuthTokenResponse();
            response.setRequestToken(requestToken);
            response.setExpiresIn(600); // 10 minutes
            response.setTokenType("AAuth");
            
            logger.debugf("Issued request_token for agent: %s, resource: %s (user consent required)", agentId, resourceId);
            
            return cors.add(Response.ok(response, MediaType.APPLICATION_JSON_TYPE));
        }

        // Direct grant - no user consent needed
        // Evaluate authorization policy
        if (!isAuthorized(session, realm, agentId, resourceId, grantedScope)) {
            throw new CorsErrorResponseException(cors, OAuthErrorException.ACCESS_DENIED,
                    "Authorization denied", Response.Status.FORBIDDEN);
        }

        // Create auth token
        AAuthTokenManager tokenManager = new AAuthTokenManager(session);
        String authToken = tokenManager.createAuthToken(realm, agentId, agentDelegate, 
                agentPublicKey, resourceId, grantedScope, null);

        // Create response
        AAuthTokenResponse response = new AAuthTokenResponse();
        response.setAuthToken(authToken);
        response.setExpiresIn(tokenManager.getTokenExpiration(realm));
        response.setTokenType("AAuth");

        logger.debugf("Issued auth token for agent: %s, resource: %s", agentId, resourceId);

        return cors.add(Response.ok(response, MediaType.APPLICATION_JSON_TYPE));
    }

    /**
     * Determine if user consent is required for this authorization request.
     * 
     * Phase 3: Basic policy - require consent for user-specific scopes.
     */
    private boolean requiresUserConsent(RealmModel realm, String scope, String resourceId) {
        if (scope != null && !scope.trim().isEmpty()) {
            String[] scopes = scope.split("\\s+");
            for (String s : scopes) {
                if (isUserScope(s)) {
                    return true;
                }
            }
        }
        // Future: Check resource-specific policies, user context requirements, etc.
        return false;
    }

    /**
     * Check if a scope requires user consent.
     */
    private boolean isUserScope(String scope) {
        // User-specific scopes that require consent
        return "profile".equals(scope) || 
               "email".equals(scope) || 
               "openid".equals(scope) ||
               scope.startsWith("user.") ||
               scope.startsWith("profile.") ||
               scope.startsWith("email.");
    }

    /**
     * Authorization check using policy evaluator.
     */
    private boolean isAuthorized(KeycloakSession session, RealmModel realm, String agentId, 
                                 String resourceId, String scope) {
        AAuthPolicyEvaluator policyEvaluator = DefaultAAuthPolicyEvaluator.create(session);
        return policyEvaluator.isAgentScopeAllowed(agentId, scope, realm);
    }

    @Override
    public void close() {
        // No cleanup needed
    }
}

