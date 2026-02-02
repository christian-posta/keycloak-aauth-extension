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
import org.keycloak.protocol.oidc.grants.OAuth2GrantType;
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

/**
 * Token endpoint for AAuth protocol.
 * 
 * Similar to TokenEndpoint but for AAuth protocol. Agent identity is extracted
 * from HTTPSig signature by AAuthSignatureFilter, not from client authentication.
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
    public Response processGrantRequest() {
        cors = Cors.builder().auth().allowedMethods("POST").auth().exposedHeaders(Cors.ACCESS_CONTROL_ALLOW_METHODS);

        MultivaluedMap<String, String> formParameters = request.getDecodedFormParameters();

        if (formParameters == null) {
            formParameters = new MultivaluedHashMap<>();
        }

        formParams = formParameters;
        requestType = formParams.getFirst("request_type");

        // Default to "auth" if request_type is not provided
        if (requestType == null) {
            requestType = "auth";
        }

        // Set cache control headers
        httpResponse.setHeader("Cache-Control", "no-store");
        httpResponse.setHeader("Pragma", "no-cache");

        checkSsl();
        checkRealm();
        checkRequestType();

        // Check parameter duplication
        checkParameterDuplicated();

        // Create grant type context
        // Note: For AAuth, we don't have a ClientModel - agent identity comes from HTTPSig
        OAuth2GrantType.Context context = new OAuth2GrantType.Context(session, null, null, formParams, event, cors, null);
        context.setClient(null); // No client for AAuth
        // Note: grantType field is protected, but it's set from formParams in constructor
        // We need to ensure request_type is in formParams for the grant type to work

        return grant.process(context);
    }

    @OPTIONS
    public Response preflight() {
        if (logger.isDebugEnabled()) {
            logger.debugv("CORS preflight from: {0}", headers.getRequestHeaders().getFirst("Origin"));
        }
        return Cors.builder().auth().preflight().allowedMethods("POST", "OPTIONS").add(Response.ok());
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
        // Get grant type provider for the request_type
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

