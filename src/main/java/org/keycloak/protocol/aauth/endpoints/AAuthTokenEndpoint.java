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

package org.keycloak.protocol.aauth.endpoints;

import org.jboss.logging.Logger;
import org.keycloak.OAuthErrorException;
import org.keycloak.common.ClientConnection;
import org.keycloak.events.EventBuilder;
import org.keycloak.http.HttpRequest;
import org.keycloak.http.HttpResponse;
import org.keycloak.models.KeycloakSession;
import org.keycloak.models.RealmModel;
import org.keycloak.protocol.aauth.AAuthTokenManager;
import org.keycloak.protocol.oidc.grants.OAuth2GrantType;
import org.keycloak.representations.AAuthTokenResponse;
import org.keycloak.services.CorsErrorResponseException;
import org.keycloak.services.cors.Cors;

import jakarta.ws.rs.Consumes;
import jakarta.ws.rs.OPTIONS;
import jakarta.ws.rs.POST;
import jakarta.ws.rs.core.HttpHeaders;
import jakarta.ws.rs.core.MediaType;
import jakarta.ws.rs.core.MultivaluedHashMap;
import jakarta.ws.rs.core.MultivaluedMap;
import jakarta.ws.rs.core.Response;
import jakarta.ws.rs.core.Response.Status;

import java.security.PublicKey;
import java.util.Map;

/**
 * Token endpoint for AAuth protocol.
 *
 * Accepts both form-encoded and JSON request bodies.
 * Auto-detects the request mode from which parameters are present:
 *   resource_token only            → resource access
 *   resource_token + upstream_token → call chaining (exchange)
 *   scope only                     → self-access
 *   auth_token                     → token refresh (re-present expired token)
 *
 * Legacy request_type=exchange routing is also supported for backward compat.
 */
public class AAuthTokenEndpoint {

    private static final Logger logger = Logger.getLogger(AAuthTokenEndpoint.class);

    private MultivaluedMap<String, String> formParams;
    private final KeycloakSession session;
    private final HttpRequest request;
    private final HttpResponse httpResponse;
    private final HttpHeaders headers;
    private final ClientConnection clientConnection;
    private final RealmModel realm;
    private final EventBuilder event;
    private String requestType;
    private OAuth2GrantType grant;
    private Cors cors;

    public AAuthTokenEndpoint(KeycloakSession session, EventBuilder event) {
        this.session = session;
        this.clientConnection = session.getContext().getConnection();
        this.realm = session.getContext().getRealm();
        this.event = event;
        this.request = session.getContext().getHttpRequest();
        this.httpResponse = session.getContext().getHttpResponse();
        this.headers = session.getContext().getRequestHeaders();
    }

    @Consumes(MediaType.APPLICATION_FORM_URLENCODED)
    @POST
    public Response processFormRequest() {
        MultivaluedMap<String, String> formParameters = request.getDecodedFormParameters();
        if (formParameters == null) {
            formParameters = new MultivaluedHashMap<>();
        }
        return processRequest(formParameters);
    }

    @Consumes(MediaType.APPLICATION_JSON)
    @POST
    public Response processJsonRequest(Map<String, Object> jsonBody) {
        // Convert JSON body to MultivaluedMap for reuse of form processing logic
        MultivaluedMap<String, String> params = new MultivaluedHashMap<>();
        if (jsonBody != null) {
            for (Map.Entry<String, Object> entry : jsonBody.entrySet()) {
                if (entry.getValue() != null) {
                    params.putSingle(entry.getKey(), entry.getValue().toString());
                }
            }
        }
        return processRequest(params);
    }

    @OPTIONS
    public Response preflight() {
        if (logger.isDebugEnabled()) {
            logger.debugv("CORS preflight from: {0}", headers.getRequestHeaders().getFirst("Origin"));
        }
        return Cors.builder().auth().preflight().allowedMethods("POST", "OPTIONS").add(Response.ok());
    }

    private Response processRequest(MultivaluedMap<String, String> params) {
        cors = Cors.builder().auth().allowedMethods("POST").auth()
                .exposedHeaders(Cors.ACCESS_CONTROL_ALLOW_METHODS);

        formParams = params;

        httpResponse.setHeader("Cache-Control", "no-store");
        httpResponse.setHeader("Pragma", "no-cache");

        checkSsl();
        checkRealm();

        // Check for token refresh mode: agent presents an expired auth_token
        String authToken = formParams.getFirst("auth_token");
        if (authToken != null && !authToken.isEmpty()
                && formParams.getFirst("resource_token") == null) {
            return handleTokenRefresh(authToken);
        }

        // Auto-detect request_type if not supplied
        requestType = formParams.getFirst("request_type");
        if (requestType == null) {
            requestType = autoDetectRequestType(formParams);
        }

        checkRequestType();
        checkParameterDuplicated();

        OAuth2GrantType.Context context = new OAuth2GrantType.Context(
                session, null, null, formParams, event, cors, null);
        context.setClient(null);

        return grant.process(context);
    }

    /**
     * Auto-detect the grant type from the parameters present.
     */
    private String autoDetectRequestType(MultivaluedMap<String, String> params) {
        boolean hasResourceToken = params.getFirst("resource_token") != null;
        boolean hasUpstreamToken = params.getFirst("upstream_token") != null
                || session.getAttribute("aauth.upstream.auth.token") != null;
        boolean hasScope = params.getFirst("scope") != null;

        if (hasResourceToken && hasUpstreamToken) {
            // Also inject upstream_token into formParams for ExchangeGrantType if it
            // came via the session attribute (JWT scheme)
            if (params.getFirst("upstream_token") == null) {
                String upstreamToken = (String) session.getAttribute("aauth.upstream.auth.token");
                if (upstreamToken != null) {
                    params.putSingle("upstream_token", upstreamToken);
                }
            }
            return "exchange";
        }
        if (hasResourceToken) {
            return "auth";
        }
        if (hasScope) {
            return "auth";
        }
        return "auth"; // default
    }

    /**
     * Handle token refresh: agent re-presents an expired auth_token to get a new one.
     */
    private Response handleTokenRefresh(String expiredAuthToken) {
        event.event(org.keycloak.events.EventType.REFRESH_TOKEN);

        PublicKey agentPublicKey = (PublicKey) session.getAttribute("aauth.agent.public.key");
        if (agentPublicKey == null) {
            throw new CorsErrorResponseException(cors, OAuthErrorException.INVALID_REQUEST,
                    "Agent identity not found. Request must be signed with HTTPSig.",
                    Response.Status.UNAUTHORIZED);
        }

        try {
            AAuthTokenManager tokenManager = new AAuthTokenManager(session);
            String newAuthToken = tokenManager.refreshFromExpiredAuthToken(
                    realm, expiredAuthToken, agentPublicKey);

            AAuthTokenResponse response = new AAuthTokenResponse();
            response.setAuthToken(newAuthToken);
            response.setExpiresIn(tokenManager.getTokenExpiration(realm));

            logger.debugf("AAuth token refresh successful");
            return cors.add(Response.ok(response, MediaType.APPLICATION_JSON_TYPE));
        } catch (Exception e) {
            logger.warnf(e, "AAuth token refresh failed");
            throw new CorsErrorResponseException(cors, OAuthErrorException.INVALID_GRANT,
                    "Token refresh failed: " + e.getMessage(), Response.Status.BAD_REQUEST);
        }
    }

    private void checkSsl() {
        if (!session.getContext().getUri().getBaseUri().getScheme().equals("https")
                && realm.getSslRequired().isRequired(clientConnection)) {
            throw new CorsErrorResponseException(cors.allowAllOrigins(), OAuthErrorException.INVALID_REQUEST,
                    "HTTPS required", Response.Status.FORBIDDEN);
        }
    }

    private void checkRealm() {
        if (!realm.isEnabled()) {
            throw new CorsErrorResponseException(cors.allowAllOrigins(), "access_denied",
                    "Realm not enabled", Response.Status.FORBIDDEN);
        }
    }

    private void checkRequestType() {
        grant = session.getProvider(OAuth2GrantType.class, requestType);

        if (grant == null) {
            throw new CorsErrorResponseException(cors, OAuthErrorException.UNSUPPORTED_GRANT_TYPE,
                    "Unsupported request_type: " + requestType, Status.BAD_REQUEST);
        }

        event.event(grant.getEventType());
        event.detail("request_type", requestType);
    }

    private void checkParameterDuplicated() {
        for (String key : formParams.keySet()) {
            if (formParams.get(key).size() != 1
                    && !grant.getSupportedMultivaluedRequestParameters().contains(key)) {
                throw new CorsErrorResponseException(cors, OAuthErrorException.INVALID_REQUEST,
                        "duplicated parameter: " + key, Response.Status.BAD_REQUEST);
            }
        }
    }
}
