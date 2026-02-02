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
import org.keycloak.common.util.Time;
import org.keycloak.events.EventType;
import org.keycloak.models.KeycloakSession;
import org.keycloak.models.RealmModel;
import org.keycloak.models.UserModel;
import org.keycloak.models.UserSessionModel;
import org.keycloak.protocol.aauth.AAuthTokenManager;
import org.keycloak.protocol.aauth.storage.AAuthAuthorizationCode;
import org.keycloak.protocol.oidc.grants.OAuth2GrantType;
import org.keycloak.protocol.aauth.representations.AAuthTokenResponse;
import org.keycloak.services.CorsErrorResponseException;
import org.keycloak.services.cors.Cors;

import jakarta.ws.rs.core.MediaType;
import jakarta.ws.rs.core.Response;

import java.security.PublicKey;
import java.util.Collections;
import java.util.Map;
import java.util.Set;

/**
 * Code grant type for AAuth protocol (request_type=code).
 * 
 * Exchanges authorization code for auth_token and refresh_token.
 * Validates agent signature matches original request.
 */
public class CodeGrantType implements OAuth2GrantType {

    private static final Logger logger = Logger.getLogger(CodeGrantType.class);

    @Override
    public EventType getEventType() {
        return EventType.CODE_TO_TOKEN;
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
        if (agentId == null && "hwk".equals(signatureScheme)) {
            AAuthTokenManager tokenManager = new AAuthTokenManager(session);
            String agentJkt = tokenManager.calculateAgentJkt(agentPublicKey);
            agentId = "pseudonymous:" + agentJkt;
        } else if (agentId == null) {
            throw new CorsErrorResponseException(cors, OAuthErrorException.INVALID_REQUEST,
                    "Agent identity not found. Request must be signed with HTTPSig.", Response.Status.UNAUTHORIZED);
        }

        // Extract code parameter
        String code = context.getFormParams().getFirst("code");
        if (code == null || code.isEmpty()) {
            throw new CorsErrorResponseException(cors, OAuthErrorException.INVALID_REQUEST,
                    "Missing required parameter: code", Response.Status.BAD_REQUEST);
        }

        String redirectUri = context.getFormParams().getFirst("redirect_uri");

        return processCodeExchange(session, realm, cors, agentId, agentPublicKey, code, redirectUri);
    }

    private Response processCodeExchange(KeycloakSession session, RealmModel realm, Cors cors,
            String agentId, PublicKey agentPublicKey, String code, String redirectUri) {
        
        // Parse and validate authorization code
        AAuthAuthorizationCode codeData = parseAndValidateCode(session, realm, code);
        if (codeData == null) {
            throw new CorsErrorResponseException(cors, OAuthErrorException.INVALID_GRANT,
                    "Invalid or expired authorization code", Response.Status.BAD_REQUEST);
        }

        // Verify redirect_uri matches
        if (redirectUri != null && !redirectUri.equals(codeData.getRedirectUriParam())) {
            throw new CorsErrorResponseException(cors, OAuthErrorException.INVALID_GRANT,
                    "redirect_uri mismatch", Response.Status.BAD_REQUEST);
        }

        // Verify agent signature matches original request
        AAuthTokenManager tokenManager = new AAuthTokenManager(session);
        String agentJkt = tokenManager.calculateAgentJkt(agentPublicKey);
        
        if (!agentId.equals(codeData.getAgentId()) || !agentJkt.equals(codeData.getAgentJkt())) {
            logger.warnf("Agent signature mismatch for code exchange. Expected agent: %s, JKT: %s, Got agent: %s, JKT: %s",
                    codeData.getAgentId(), codeData.getAgentJkt(), agentId, agentJkt);
            throw new CorsErrorResponseException(cors, OAuthErrorException.INVALID_GRANT,
                    "Agent signature mismatch", Response.Status.BAD_REQUEST);
        }

        // Get user session
        UserSessionModel userSession = session.sessions().getUserSession(realm, codeData.getUserSessionId());
        if (userSession == null) {
            throw new CorsErrorResponseException(cors, OAuthErrorException.INVALID_GRANT,
                    "User session not found", Response.Status.BAD_REQUEST);
        }

        UserModel user = userSession.getUser();
        if (user == null) {
            throw new CorsErrorResponseException(cors, OAuthErrorException.INVALID_GRANT,
                    "User not found", Response.Status.BAD_REQUEST);
        }

        // Create auth token with user identity
        String authToken = tokenManager.createAuthToken(realm, agentId, null, agentPublicKey,
                codeData.getResourceId(), codeData.getScope(), user);

        // Create refresh token with agent binding
        String refreshToken = tokenManager.createRefreshToken(realm, agentId, agentJkt, null,
                codeData.getResourceId(), codeData.getScope(), user, agentPublicKey);

        // Create response
        AAuthTokenResponse response = new AAuthTokenResponse();
        response.setAuthToken(authToken);
        response.setExpiresIn(tokenManager.getTokenExpiration(realm));
        response.setRefreshToken(refreshToken);
        response.setTokenType("AAuth");

        logger.debugf("Exchanged code for auth token. Agent: %s, User: %s, Resource: %s",
                agentId, user.getId(), codeData.getResourceId());

        return cors.add(Response.ok(response, MediaType.APPLICATION_JSON_TYPE));
    }

    private AAuthAuthorizationCode parseAndValidateCode(KeycloakSession session, RealmModel realm, String code) {
        if (code == null || code.isEmpty()) {
            return null;
        }

        String[] parts = code.split("\\.", 3);
        if (parts.length != 3) {
            logger.warn("Invalid authorization code format");
            return null;
        }

        String codeId = parts[0];
        String userSessionId = parts[1];

        // Retrieve code from store
        Map<String, String> codeDataMap = session.singleUseObjects().remove(codeId);
        if (codeDataMap == null) {
            logger.debugf("Authorization code not found or already used: %s", codeId);
            return null;
        }

        AAuthAuthorizationCode codeData = AAuthAuthorizationCode.deserialize(codeDataMap);

        // Check expiration
        if (Time.currentTime() > codeData.getExpiration()) {
            logger.debugf("Authorization code expired: %s", codeId);
            return null;
        }

        // Verify user session ID matches
        if (!userSessionId.equals(codeData.getUserSessionId())) {
            logger.warnf("User session ID mismatch in authorization code");
            return null;
        }

        return codeData;
    }


    @Override
    public void close() {
        // No cleanup needed
    }
}

