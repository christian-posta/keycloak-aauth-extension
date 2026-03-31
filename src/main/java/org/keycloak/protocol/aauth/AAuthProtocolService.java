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
import org.keycloak.protocol.aauth.endpoints.AAuthPendingEndpoint;
import org.keycloak.protocol.aauth.endpoints.AAuthTokenEndpoint;
import org.keycloak.protocol.oidc.utils.JWKSServerUtils;
import org.keycloak.services.cors.Cors;
import org.keycloak.services.util.CacheControlUtil;

import jakarta.ws.rs.GET;
import jakarta.ws.rs.OPTIONS;
import jakarta.ws.rs.Path;
import jakarta.ws.rs.PathParam;
import jakarta.ws.rs.Produces;
import jakarta.ws.rs.core.MediaType;
import jakarta.ws.rs.core.Response;

/**
 * Resource class for AAuth protocol endpoints.
 *
 * Endpoint paths (per updated AAuth spec):
 *   POST /token          - Token endpoint (was /agent/token)
 *   GET  /interact       - Interaction endpoint (was /agent/auth)
 *   GET  /pending/{id}   - Pending request polling endpoint (new)
 *   GET  /certs          - JWKS public keys
 *
 * Legacy paths kept for backward compatibility during migration:
 *   /agent/token → /token
 *   /agent/auth  → /interact
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

    /** Token endpoint - primary path per updated spec */
    @Path("token")
    public Object token() {
        return new AAuthTokenEndpoint(session, event);
    }

    /** Token endpoint - legacy path for backward compatibility */
    @Path("agent/token")
    public Object agentToken() {
        return new AAuthTokenEndpoint(session, event);
    }

    /** Interaction endpoint - primary path per updated spec */
    @Path("interact")
    public Object interact() {
        return new AAuthAuthorizationEndpoint(session, event);
    }

    /** Interaction endpoint - legacy path for backward compatibility */
    @Path("agent/auth")
    public Object agentAuth() {
        return new AAuthAuthorizationEndpoint(session, event);
    }

    /** Pending request polling endpoint */
    @Path("pending/{id}")
    public Object pending(@PathParam("id") String pendingId) {
        return new AAuthPendingEndpoint(session, event, pendingId);
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
