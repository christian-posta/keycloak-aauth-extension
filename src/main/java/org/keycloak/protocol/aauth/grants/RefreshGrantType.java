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
import org.keycloak.common.VerificationException;
import org.keycloak.events.EventType;
import org.keycloak.models.KeycloakSession;
import org.keycloak.models.RealmModel;
import org.keycloak.protocol.aauth.AAuthTokenManager;
import org.keycloak.protocol.aauth.policy.AAuthPolicyEvaluator;
import org.keycloak.protocol.aauth.policy.DefaultAAuthPolicyEvaluator;
import org.keycloak.protocol.oidc.grants.OAuth2GrantType;
import org.keycloak.protocol.aauth.representations.AAuthRefreshToken;
import org.keycloak.protocol.aauth.representations.AAuthTokenResponse;
import org.keycloak.services.CorsErrorResponseException;
import org.keycloak.services.cors.Cors;

import jakarta.ws.rs.core.MediaType;
import jakarta.ws.rs.core.Response;

import java.security.PublicKey;
import java.util.Collections;
import java.util.Set;

/**
 * Refresh grant type for AAuth protocol (request_type=refresh).
 * 
 * Refreshes an expired auth_token using a refresh_token.
 * Validates agent signature matches the refresh token's bound agent.
 */
public class RefreshGrantType implements OAuth2GrantType {

    private static final Logger logger = Logger.getLogger(RefreshGrantType.class);

    @Override
    public EventType getEventType() {
        return EventType.REFRESH_TOKEN;
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

        // Extract refresh_token parameter
        String refreshTokenString = context.getFormParams().getFirst("refresh_token");
        if (refreshTokenString == null || refreshTokenString.isEmpty()) {
            throw new CorsErrorResponseException(cors, OAuthErrorException.INVALID_REQUEST,
                    "Missing required parameter: refresh_token", Response.Status.BAD_REQUEST);
        }

        // Extract agent identity from session (set by AAuthSignatureFilter)
        String agentId = (String) session.getAttribute("aauth.agent.id");
        PublicKey agentPublicKey = (PublicKey) session.getAttribute("aauth.agent.public.key");
        String signatureScheme = (String) session.getAttribute("aauth.signature.scheme");

        if (agentPublicKey == null) {
            throw new CorsErrorResponseException(cors, OAuthErrorException.INVALID_REQUEST,
                    "Agent identity not found. Request must be signed with HTTPSig.", Response.Status.UNAUTHORIZED);
        }

        // For pseudonymous schemes (hwk), derive agent ID from public key
        if (agentId == null && "hwk".equals(signatureScheme)) {
            AAuthTokenManager tokenManager = new AAuthTokenManager(session);
            String agentJkt = tokenManager.calculateAgentJkt(agentPublicKey);
            agentId = "pseudonymous:" + agentJkt;
        } else if (agentId == null) {
            throw new CorsErrorResponseException(cors, OAuthErrorException.INVALID_REQUEST,
                    "Agent identity not found. Request must be signed with HTTPSig.", Response.Status.UNAUTHORIZED);
        }

        return processRefresh(session, realm, cors, agentId, agentPublicKey, refreshTokenString);
    }

    private Response processRefresh(KeycloakSession session, RealmModel realm, Cors cors,
            String agentId, PublicKey agentPublicKey, String refreshTokenString) {

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

        AAuthTokenManager tokenManager = new AAuthTokenManager(session);

        try {
            // Validate refresh token
            AAuthRefreshToken refreshToken = tokenManager.validateRefreshToken(realm, refreshTokenString);

            // Verify agent binding
            verifyAgentBinding(agentId, agentPublicKey, refreshToken, tokenManager);

            // Generate new auth token
            String newAuthToken = tokenManager.refreshAuthToken(realm, refreshToken, agentPublicKey);

            // Create response
            AAuthTokenResponse response = new AAuthTokenResponse();
            response.setAuthToken(newAuthToken);
            response.setExpiresIn(tokenManager.getTokenExpiration(realm));
            response.setTokenType("AAuth");

            logger.debugf("Refreshed auth token for agent: %s, resource: %s", 
                    refreshToken.getAgent(), refreshToken.getResourceId());

            return cors.add(Response.ok(response, MediaType.APPLICATION_JSON_TYPE));

        } catch (VerificationException e) {
            logger.warnf("Refresh token validation failed: %s", e.getMessage());
            throw new CorsErrorResponseException(cors, OAuthErrorException.INVALID_GRANT,
                    "Invalid refresh_token: " + e.getMessage(), Response.Status.BAD_REQUEST);
        } catch (Exception e) {
            logger.errorf(e, "Error refreshing token for agent: %s", agentId);
            throw new CorsErrorResponseException(cors, OAuthErrorException.INVALID_GRANT,
                    "Error refreshing token: " + e.getMessage(), Response.Status.BAD_REQUEST);
        }
    }

    /**
     * Verify that the current agent signature matches the refresh token's bound agent.
     */
    private void verifyAgentBinding(String agentId, PublicKey agentPublicKey, 
            AAuthRefreshToken refreshToken, AAuthTokenManager tokenManager) {

        String tokenAgentId = refreshToken.getAgent();
        String tokenAgentJkt = refreshToken.getAgentJkt();

        // Calculate current agent's JKT
        String currentAgentJkt = tokenManager.calculateAgentJkt(agentPublicKey);

        // Verify agent binding
        boolean agentMatches = false;

        // Check if agent IDs match
        if (agentId != null && agentId.equals(tokenAgentId)) {
            agentMatches = true;
        }

        // Check if agent JKTs match (for pseudonymous agents)
        if (tokenAgentJkt != null && tokenAgentJkt.equals(currentAgentJkt)) {
            agentMatches = true;
        }

        // If both agent ID and JKT are present, both must match
        if (tokenAgentId != null && tokenAgentJkt != null) {
            if (!agentId.equals(tokenAgentId) || !tokenAgentJkt.equals(currentAgentJkt)) {
                agentMatches = false;
            }
        }

        if (!agentMatches) {
            throw new RuntimeException("Agent signature mismatch: refresh token bound to agent " + 
                    tokenAgentId + " (JKT: " + tokenAgentJkt + "), but current request is from agent " + 
                    agentId + " (JKT: " + currentAgentJkt + ")");
        }

        // Verify agent_delegate if present
        // For Phase 4, we don't validate agent_delegate from the signature
        // This could be enhanced in the future to extract delegate from signature
        if (refreshToken.getAgentDelegate() != null) {
            // Future: validate agent_delegate matches signature
        }
    }

    @Override
    public void close() {
        // No cleanup needed
    }
}

