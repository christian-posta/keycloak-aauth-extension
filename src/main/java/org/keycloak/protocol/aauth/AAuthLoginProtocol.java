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
import org.keycloak.events.EventBuilder;
import org.keycloak.models.AuthenticatedClientSessionModel;
import org.keycloak.models.ClientModel;
import org.keycloak.models.ClientSessionContext;
import org.keycloak.models.KeycloakSession;
import org.keycloak.models.RealmModel;
import org.keycloak.models.UserSessionModel;
import org.keycloak.protocol.ClientData;
import org.keycloak.protocol.LoginProtocol;
import org.keycloak.protocol.aauth.storage.AAuthRequestToken;
import org.keycloak.protocol.aauth.storage.AAuthRequestTokenStore;
import org.keycloak.sessions.AuthenticationSessionModel;
import org.keycloak.utils.KeycloakSessionUtil;

import jakarta.ws.rs.core.HttpHeaders;
import jakarta.ws.rs.core.Response;
import jakarta.ws.rs.core.UriBuilder;
import jakarta.ws.rs.core.UriInfo;

/**
 * LoginProtocol implementation for AAuth.
 * 
 * Handles the post-authentication redirect back to the AAuth authorization endpoint.
 */
public class AAuthLoginProtocol implements LoginProtocol {

    private static final Logger logger = Logger.getLogger(AAuthLoginProtocol.class);
    
    private static final String REQUEST_TOKEN_PARAM = "request_token";
    private static final String REDIRECT_URI_PARAM = "redirect_uri";
    private static final String STATE_PARAM = "state";

    private KeycloakSession session;
    private RealmModel realm;
    private UriInfo uriInfo;
    private HttpHeaders headers;
    private EventBuilder event;

    @Override
    public LoginProtocol setSession(KeycloakSession session) {
        this.session = session;
        return this;
    }

    @Override
    public LoginProtocol setRealm(RealmModel realm) {
        this.realm = realm;
        return this;
    }

    @Override
    public LoginProtocol setUriInfo(UriInfo uriInfo) {
        this.uriInfo = uriInfo;
        return this;
    }

    @Override
    public LoginProtocol setHttpHeaders(HttpHeaders headers) {
        this.headers = headers;
        return this;
    }

    @Override
    public LoginProtocol setEventBuilder(EventBuilder event) {
        this.event = event;
        return this;
    }

    @Override
    public Response authenticated(AuthenticationSessionModel authSession, UserSessionModel userSession, ClientSessionContext clientSessionCtx) {
        // Retrieve request token from authentication session
        String requestToken = authSession.getClientNote(REQUEST_TOKEN_PARAM);
        String redirectUri = authSession.getClientNote(REDIRECT_URI_PARAM);
        String state = authSession.getClientNote(STATE_PARAM);
        
        // If request_token is not in session notes, try to extract it from state
        // (This can happen if the auth session was recreated from ClientData)
        if ((requestToken == null || requestToken.isEmpty()) && state != null && state.contains("|")) {
            String[] parts = state.split("\\|", 2);
            if (parts.length == 2) {
                state = parts[0]; // Original state
                requestToken = parts[1]; // Request token
            }
        }
        
        if (requestToken == null || requestToken.isEmpty()) {
            logger.warnf("No request_token found in authentication session after login");
            return sendError(authSession, Error.CANCELLED_BY_USER, "Missing request_token");
        }

        // Get session from thread context if not set via setSession()
        KeycloakSession currentSession = this.session != null ? this.session : KeycloakSessionUtil.getKeycloakSession();
        if (currentSession == null) {
            logger.error("KeycloakSession not available for request token validation");
            return sendError(authSession, Error.CANCELLED_BY_USER, "Internal error: session not available");
        }

        // Validate request token
        AAuthRequestTokenStore tokenStore = new AAuthRequestTokenStore(currentSession);
        AAuthRequestToken tokenData = tokenStore.validateRequestToken(requestToken);
        
        if (tokenData == null) {
            logger.warnf("Invalid or expired request_token: %s", requestToken);
            return sendError(authSession, Error.CANCELLED_BY_USER, "Invalid or expired request_token");
        }

        // Use redirect_uri from token if not in session
        if (redirectUri == null || redirectUri.isEmpty()) {
            redirectUri = tokenData.getRedirectUri();
        }

        // Redirect back to /agent/auth to show consent screen (user is now authenticated).
        // Do NOT generate auth code yet - the consent screen must be shown first.
        // After user grants consent on the consent screen, AAuthAuthorizationEndpoint
        // will generate the code and redirect to the agent.
        java.net.URI baseUri = currentSession.getContext().getUri().getBaseUri();
        UriBuilder agentAuthUri = UriBuilder.fromUri(baseUri)
                .path("realms/{realm}/protocol/aauth/agent/auth")
                .resolveTemplate("realm", realm.getName())
                .queryParam(REQUEST_TOKEN_PARAM, requestToken)
                .queryParam(REDIRECT_URI_PARAM, redirectUri);
        if (state != null && !state.isEmpty()) {
            agentAuthUri.queryParam(STATE_PARAM, state);
        }
        
        logger.debugf("Redirecting to consent screen (agent/auth) for agent: %s, resource: %s", 
                tokenData.getAgentId(), tokenData.getResourceId());
        
        return Response.seeOther(agentAuthUri.build()).build();
    }

    @Override
    public Response sendError(AuthenticationSessionModel authSession, Error error, String errorMessage) {
        String redirectUri = authSession.getClientNote(REDIRECT_URI_PARAM);
        String state = authSession.getClientNote(STATE_PARAM);
        
        if (redirectUri != null) {
            UriBuilder uriBuilder = UriBuilder.fromUri(redirectUri);
            uriBuilder.queryParam("error", error.name().toLowerCase());
            if (errorMessage != null) {
                uriBuilder.queryParam("error_description", errorMessage);
            }
            if (state != null) {
                uriBuilder.queryParam(STATE_PARAM, state);
            }
            return Response.seeOther(uriBuilder.build()).build();
        }
        
        // Return error page if no redirect URI
        return Response.status(Response.Status.BAD_REQUEST)
                .entity(String.format("{\"error\":\"%s\",\"error_description\":\"%s\"}", error.name().toLowerCase(), errorMessage))
                .build();
    }

    @Override
    public ClientData getClientData(AuthenticationSessionModel authSession) {
        // Store request_token in state field (since ClientData doesn't have a request_token field)
        // We'll reconstruct it from the state when decoding
        String redirectUri = authSession.getClientNote(REDIRECT_URI_PARAM);
        String state = authSession.getClientNote(STATE_PARAM);
        String requestToken = authSession.getClientNote(REQUEST_TOKEN_PARAM);
        
        // Encode request_token into state if present
        // Format: "original_state|request_token" or just "request_token" if no state
        String encodedState = state != null ? state + "|" + requestToken : requestToken;
        
        // Return proper ClientData that will be Base64Url-encoded as JSON
        return new ClientData(redirectUri, null, null, encodedState);
    }

    @Override
    public Response sendError(ClientModel client, ClientData clientData, Error error) {
        // Decode client data to get redirect URI and state
        String redirectUri = clientData != null ? clientData.getRedirectUri() : null;
        String state = clientData != null ? clientData.getState() : null;
        
        // Extract original state if it contains request_token (format: "original_state|request_token")
        if (state != null && state.contains("|")) {
            String[] parts = state.split("\\|", 2);
            if (parts.length == 2) {
                state = parts[0]; // Use original state for error redirect
            }
        }
        
        if (redirectUri != null) {
            UriBuilder uriBuilder = UriBuilder.fromUri(redirectUri);
            uriBuilder.queryParam("error", error.name().toLowerCase());
            if (state != null && !state.isEmpty()) {
                uriBuilder.queryParam(STATE_PARAM, state);
            }
            return Response.seeOther(uriBuilder.build()).build();
        }
        
        return Response.status(Response.Status.BAD_REQUEST)
                .entity(String.format("{\"error\":\"%s\"}", error.name().toLowerCase()))
                .build();
    }

    @Override
    public Response backchannelLogout(UserSessionModel userSession, AuthenticatedClientSessionModel clientSession) {
        // AAuth doesn't support backchannel logout in Phase 3
        return Response.ok().build();
    }

    @Override
    public Response frontchannelLogout(UserSessionModel userSession, AuthenticatedClientSessionModel clientSession) {
        // AAuth doesn't support frontchannel logout in Phase 3
        return Response.ok().build();
    }

    @Override
    public Response finishBrowserLogout(UserSessionModel userSession, AuthenticationSessionModel logoutSession) {
        // AAuth doesn't support browser logout in Phase 3
        return Response.ok().build();
    }

    @Override
    public boolean requireReauthentication(UserSessionModel userSession, AuthenticationSessionModel authSession) {
        // For Phase 3, we don't require reauthentication
        return false;
    }

    @Override
    public void close() {
        // No cleanup needed
    }
}

