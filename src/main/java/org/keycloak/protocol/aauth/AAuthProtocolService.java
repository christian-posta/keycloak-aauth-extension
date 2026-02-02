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

import org.keycloak.events.EventBuilder;
import org.keycloak.jose.jwk.JSONWebKeySet;
import org.keycloak.models.KeycloakSession;
import org.keycloak.models.RealmModel;
import org.keycloak.protocol.aauth.endpoints.AAuthAuthorizationEndpoint;
import org.keycloak.protocol.aauth.endpoints.AAuthTokenEndpoint;
import org.keycloak.protocol.oidc.utils.JWKSServerUtils;
import org.keycloak.services.cors.Cors;
import org.keycloak.services.util.CacheControlUtil;

import jakarta.ws.rs.GET;
import jakarta.ws.rs.OPTIONS;
import jakarta.ws.rs.Path;
import jakarta.ws.rs.Produces;
import jakarta.ws.rs.core.MediaType;
import jakarta.ws.rs.core.Response;

/**
 * Resource class for AAuth protocol endpoints.
 * 
 * Similar to OIDCLoginProtocolService but for AAuth protocol.
 */
public class AAuthProtocolService {

    private final RealmModel realm;
    private final EventBuilder event;
    private final KeycloakSession session;

    public AAuthProtocolService(KeycloakSession session, EventBuilder event) {
        this.session = session;
        this.realm = session.getContext().getRealm();
        this.event = event;
    }

    /**
     * Agent token endpoint for auth requests, code exchange, token exchange, and refresh.
     */
    @Path("agent/token")
    public Object agentToken() {
        return new AAuthTokenEndpoint(session, event);
    }

    /**
     * Agent auth endpoint for user authentication and consent flow (Phase 3).
     */
    @Path("agent/auth")
    public Object agentAuth() {
        return new AAuthAuthorizationEndpoint(session, event);
    }

    @OPTIONS
    @Path("certs")
    @Produces(MediaType.APPLICATION_JSON)
    public Response getVersionPreflight() {
        return Cors.builder().allowedMethods("GET").preflight().auth().add(Response.ok());
    }

    @GET
    @Path("certs")
    @Produces(MediaType.APPLICATION_JSON)
    public Response certs() {
        JSONWebKeySet keySet = JWKSServerUtils.getRealmJwks(session, realm);

        Response.ResponseBuilder responseBuilder = Response.ok(keySet)
                .cacheControl(CacheControlUtil.getDefaultCacheControl());
        return Cors.builder().allowedOrigins("*").auth().add(responseBuilder);
    }
}

