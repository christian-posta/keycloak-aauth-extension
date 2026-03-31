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
import org.keycloak.protocol.aauth.storage.AAuthPendingRequest;
import org.keycloak.protocol.aauth.storage.AAuthPendingRequestStore;
import org.keycloak.sessions.AuthenticationSessionModel;
import org.keycloak.utils.KeycloakSessionUtil;

import jakarta.ws.rs.core.HttpHeaders;
import jakarta.ws.rs.core.Response;
import jakarta.ws.rs.core.UriBuilder;
import jakarta.ws.rs.core.UriInfo;

/**
 * LoginProtocol implementation for AAuth.
 *
 * After user login, redirects back to the interaction endpoint using the
 * interaction code stored in the auth session.
 */
public class AAuthLoginProtocol implements LoginProtocol {

    private static final Logger logger = Logger.getLogger(AAuthLoginProtocol.class);

    /** Auth session note keys */
    private static final String INTERACTION_CODE_PARAM = "code";
    private static final String PENDING_ID_PARAM = "pending_id";
    private static final String CALLBACK_PARAM = "callback";
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
    public Response authenticated(AuthenticationSessionModel authSession,
            UserSessionModel userSession, ClientSessionContext clientSessionCtx) {

        String interactionCode = authSession.getClientNote(INTERACTION_CODE_PARAM);
        String pendingId = authSession.getClientNote(PENDING_ID_PARAM);
        String callbackUrl = authSession.getClientNote(CALLBACK_PARAM);
        String state = authSession.getClientNote(STATE_PARAM);

        if (interactionCode == null && pendingId == null) {
            logger.warn("AAuth: no interaction code or pending_id in auth session after login");
            return sendError(authSession, Error.CANCELLED_BY_USER, "Missing interaction code");
        }

        KeycloakSession currentSession = this.session != null ? this.session : KeycloakSessionUtil.getKeycloakSession();
        if (currentSession == null) {
            logger.error("KeycloakSession not available after login");
            return sendError(authSession, Error.CANCELLED_BY_USER, "Internal error: session not available");
        }

        // If we only have pendingId, look up the interaction code from the pending store
        if (interactionCode == null) {
            AAuthPendingRequestStore pendingStore = new AAuthPendingRequestStore(currentSession);
            AAuthPendingRequest pending = pendingStore.getPendingRequest(pendingId);
            if (pending != null) {
                interactionCode = pending.getInteractionCode();
            }
        }

        // Redirect back to /interact?code=... to show consent screen
        java.net.URI baseUri = currentSession.getContext().getUri().getBaseUri();
        UriBuilder interactUri = UriBuilder.fromUri(baseUri)
                .path("realms/{realm}/protocol/aauth/interact")
                .resolveTemplate("realm", realm.getName());

        if (interactionCode != null) {
            interactUri.queryParam(INTERACTION_CODE_PARAM, interactionCode);
        } else if (pendingId != null) {
            interactUri.queryParam(PENDING_ID_PARAM, pendingId);
        }

        if (callbackUrl != null && !callbackUrl.isEmpty()) {
            interactUri.queryParam(CALLBACK_PARAM, callbackUrl);
        }
        if (state != null && !state.isEmpty()) {
            interactUri.queryParam(STATE_PARAM, state);
        }

        logger.debugf("AAuth: redirecting to interact endpoint after login, code=%s", interactionCode);
        return Response.seeOther(interactUri.build()).build();
    }

    @Override
    public Response sendError(AuthenticationSessionModel authSession, Error error, String errorMessage) {
        String callbackUrl = authSession.getClientNote(CALLBACK_PARAM);
        String state = authSession.getClientNote(STATE_PARAM);

        if (callbackUrl != null && !callbackUrl.isEmpty()) {
            UriBuilder uriBuilder = UriBuilder.fromUri(callbackUrl);
            uriBuilder.queryParam("error", error.name().toLowerCase());
            if (errorMessage != null) {
                uriBuilder.queryParam("error_description", errorMessage);
            }
            if (state != null) {
                uriBuilder.queryParam(STATE_PARAM, state);
            }
            return Response.seeOther(uriBuilder.build()).build();
        }

        return Response.status(Response.Status.BAD_REQUEST)
                .entity(String.format("{\"error\":\"%s\",\"error_description\":\"%s\"}",
                        error.name().toLowerCase(), errorMessage))
                .build();
    }

    @Override
    public ClientData getClientData(AuthenticationSessionModel authSession) {
        String callbackUrl = authSession.getClientNote(CALLBACK_PARAM);
        String state = authSession.getClientNote(STATE_PARAM);
        String interactionCode = authSession.getClientNote(INTERACTION_CODE_PARAM);
        String pendingId = authSession.getClientNote(PENDING_ID_PARAM);

        // Encode interaction code + pending_id in state so we can recover them
        String encodedState = (state != null ? state : "") + "|"
                + (interactionCode != null ? interactionCode : "") + "|"
                + (pendingId != null ? pendingId : "");

        return new ClientData(callbackUrl, null, null, encodedState);
    }

    @Override
    public Response sendError(ClientModel client, ClientData clientData, Error error) {
        String callbackUrl = clientData != null ? clientData.getRedirectUri() : null;

        if (callbackUrl != null && !callbackUrl.isEmpty()) {
            UriBuilder uriBuilder = UriBuilder.fromUri(callbackUrl);
            uriBuilder.queryParam("error", error.name().toLowerCase());
            return Response.seeOther(uriBuilder.build()).build();
        }

        return Response.status(Response.Status.BAD_REQUEST)
                .entity(String.format("{\"error\":\"%s\"}", error.name().toLowerCase()))
                .build();
    }

    @Override
    public Response backchannelLogout(UserSessionModel userSession, AuthenticatedClientSessionModel clientSession) {
        return Response.ok().build();
    }

    @Override
    public Response frontchannelLogout(UserSessionModel userSession, AuthenticatedClientSessionModel clientSession) {
        return Response.ok().build();
    }

    @Override
    public Response finishBrowserLogout(UserSessionModel userSession, AuthenticationSessionModel logoutSession) {
        return Response.ok().build();
    }

    @Override
    public boolean requireReauthentication(UserSessionModel userSession, AuthenticationSessionModel authSession) {
        return false;
    }

    @Override
    public void close() {}
}
