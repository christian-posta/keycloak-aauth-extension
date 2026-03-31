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
import org.keycloak.common.util.Time;
import org.keycloak.events.EventBuilder;
import org.keycloak.models.KeycloakSession;
import org.keycloak.models.RealmModel;
import org.keycloak.protocol.aauth.storage.AAuthPendingRequest;
import org.keycloak.protocol.aauth.storage.AAuthPendingRequestStore;
import org.keycloak.services.cors.Cors;

import jakarta.ws.rs.Consumes;
import jakarta.ws.rs.GET;
import jakarta.ws.rs.POST;
import jakarta.ws.rs.core.MediaType;
import jakarta.ws.rs.core.Response;

import java.security.PublicKey;
import java.util.LinkedHashMap;
import java.util.Map;

/**
 * Pending URL endpoint for the 202-deferred flow.
 *
 * Agents poll GET /protocol/aauth/pending/{id} to retrieve the result of
 * a pending authorization request.
 *
 * Response lifecycle:
 *   202 Accepted          → still waiting for user interaction/approval
 *   200 OK                → completed: body contains auth_token
 *   403 Forbidden         → user denied (or policy denied)
 *   408 Request Timeout   → pending request expired
 *   404 Not Found         → unknown id (or already delivered terminal response)
 *
 * After a terminal response is returned (200/403/408), the pending entry is
 * consumed so subsequent polls return 404.
 *
 * Agent identity is verified by AAuthSignatureFilter before this handler runs.
 * We additionally verify the polling agent matches the requesting agent via agentJkt.
 */
public class AAuthPendingEndpoint {

    private static final Logger logger = Logger.getLogger(AAuthPendingEndpoint.class);

    private final KeycloakSession session;
    private final EventBuilder event;
    private final String pendingId;
    private final RealmModel realm;

    public AAuthPendingEndpoint(KeycloakSession session, EventBuilder event, String pendingId) {
        this.session = session;
        this.event = event;
        this.pendingId = pendingId;
        this.realm = session.getContext().getRealm();
    }

    @GET
    public Response poll() {
        Cors cors = Cors.builder().auth().allowedMethods("GET");

        AAuthPendingRequestStore store = new AAuthPendingRequestStore(session);
        AAuthPendingRequest pending = store.getPendingRequest(pendingId);

        if (pending == null) {
            return cors.add(Response.status(Response.Status.NOT_FOUND)
                    .entity(Map.of("error", "not_found", "error_description", "Pending request not found or expired"))
                    .type(MediaType.APPLICATION_JSON_TYPE));
        }

        // Verify agent identity matches the original requester
        String pollingAgentJkt = getPollingAgentJkt();
        if (pollingAgentJkt != null && pending.getAgentJkt() != null
                && !pollingAgentJkt.equals(pending.getAgentJkt())) {
            logger.warnf("Pending endpoint: agent JKT mismatch: expected=%s, got=%s",
                    pending.getAgentJkt(), pollingAgentJkt);
            return cors.add(Response.status(Response.Status.FORBIDDEN)
                    .entity(Map.of("error", "access_denied", "error_description", "Agent identity mismatch"))
                    .type(MediaType.APPLICATION_JSON_TYPE));
        }

        // Check if expired
        if (Time.currentTime() > pending.getExpiresAt()) {
            store.consumePendingRequest(pendingId);
            return cors.add(Response.status(408)
                    .entity(Map.of("error", "expired", "error_description", "Pending request has expired"))
                    .type(MediaType.APPLICATION_JSON_TYPE));
        }

        switch (pending.getStatus()) {
            case AAuthPendingRequest.STATUS_COMPLETED: {
                // Consume and return auth token
                store.consumePendingRequest(pendingId);
                Map<String, Object> body = new LinkedHashMap<>();
                body.put("auth_token", pending.getAuthToken());
                body.put("expires_in", pending.getExpiresIn());
                logger.infof("Pending request completed, returning auth_token: id=%s, agent=%s",
                        pendingId, pending.getAgentId());
                return cors.add(Response.ok(body, MediaType.APPLICATION_JSON_TYPE));
            }

            case AAuthPendingRequest.STATUS_DENIED: {
                store.consumePendingRequest(pendingId);
                Map<String, Object> body = new LinkedHashMap<>();
                body.put("error", pending.getError() != null ? pending.getError() : "access_denied");
                if (pending.getErrorDescription() != null) {
                    body.put("error_description", pending.getErrorDescription());
                }
                logger.infof("Pending request denied: id=%s, agent=%s", pendingId, pending.getAgentId());
                return cors.add(Response.status(Response.Status.FORBIDDEN)
                        .entity(body)
                        .type(MediaType.APPLICATION_JSON_TYPE));
            }

            case AAuthPendingRequest.STATUS_EXPIRED: {
                store.consumePendingRequest(pendingId);
                return cors.add(Response.status(408)
                        .entity(Map.of("error", "expired", "error_description", "Pending request has expired"))
                        .type(MediaType.APPLICATION_JSON_TYPE));
            }

            case AAuthPendingRequest.STATUS_AWAITING_CLARIFICATION:
            case AAuthPendingRequest.STATUS_PENDING:
            default: {
                // Build pending URL path
                String pendingPath = buildPendingPath();

                Map<String, Object> body = new LinkedHashMap<>();
                body.put("status", AAuthPendingRequest.STATUS_AWAITING_CLARIFICATION.equals(pending.getStatus())
                        ? "awaiting_clarification" : "pending");
                body.put("location", pendingPath);
                body.put("require", pending.getRequireType());

                if (AAuthPendingRequest.REQUIRE_INTERACTION.equals(pending.getRequireType())
                        && pending.getInteractionCode() != null) {
                    body.put("code", pending.getInteractionCode());
                }

                // Include clarification question if the user has asked one
                if (pending.getClarification() != null) {
                    body.put("clarification", pending.getClarification());
                }

                // Build AAuth response header value
                String aAuthHeader = buildAAuthHeader(pending);

                logger.debugf("Pending request still waiting: id=%s, require=%s, hasClarification=%s",
                        pendingId, pending.getRequireType(), pending.getClarification() != null);

                return cors.add(Response.status(202)
                        .header("Location", pendingPath)
                        .header("Retry-After", "0")
                        .header("Cache-Control", "no-store")
                        .header("AAuth", aAuthHeader)
                        .entity(body)
                        .type(MediaType.APPLICATION_JSON_TYPE));
            }
        }
    }

    /**
     * Agent posts a clarification response to the pending URL.
     * Body: { "clarification_response": "..." }
     */
    @POST
    @Consumes(MediaType.APPLICATION_JSON)
    public Response submitClarificationResponse(Map<String, Object> body) {
        Cors cors = Cors.builder().auth().allowedMethods("POST");

        AAuthPendingRequestStore store = new AAuthPendingRequestStore(session);
        AAuthPendingRequest pending = store.getPendingRequest(pendingId);

        if (pending == null) {
            return cors.add(Response.status(Response.Status.NOT_FOUND)
                    .entity(Map.of("error", "not_found", "error_description", "Pending request not found or expired"))
                    .type(MediaType.APPLICATION_JSON_TYPE));
        }

        // Verify agent identity
        String pollingAgentJkt = getPollingAgentJkt();
        if (pollingAgentJkt != null && pending.getAgentJkt() != null
                && !pollingAgentJkt.equals(pending.getAgentJkt())) {
            return cors.add(Response.status(Response.Status.FORBIDDEN)
                    .entity(Map.of("error", "access_denied", "error_description", "Agent identity mismatch"))
                    .type(MediaType.APPLICATION_JSON_TYPE));
        }

        // Check if clarification is expected
        if (!AAuthPendingRequest.STATUS_AWAITING_CLARIFICATION.equals(pending.getStatus())) {
            return cors.add(Response.status(Response.Status.BAD_REQUEST)
                    .entity(Map.of("error", "invalid_request",
                            "error_description", "No clarification question is pending"))
                    .type(MediaType.APPLICATION_JSON_TYPE));
        }

        Object responseObj = body != null ? body.get("clarification_response") : null;
        if (responseObj == null) {
            return cors.add(Response.status(Response.Status.BAD_REQUEST)
                    .entity(Map.of("error", "invalid_request",
                            "error_description", "Missing clarification_response field"))
                    .type(MediaType.APPLICATION_JSON_TYPE));
        }

        String clarificationResponse = responseObj.toString();
        store.setClarificationResponse(pendingId, clarificationResponse);

        logger.infof("Received clarification response for pending request id=%s, agent=%s",
                pendingId, pending.getAgentId());

        Map<String, Object> result = new LinkedHashMap<>();
        result.put("status", "clarification_received");
        return cors.add(Response.ok(result, MediaType.APPLICATION_JSON_TYPE));
    }

    private String getPollingAgentJkt() {
        // Agent JKT was stored by AAuthSignatureFilter via session attribute
        // We calculate it from the public key
        PublicKey agentPublicKey = (PublicKey) session.getAttribute("aauth.agent.public.key");
        if (agentPublicKey == null) return null;
        org.keycloak.protocol.aauth.AAuthTokenManager tokenManager =
                new org.keycloak.protocol.aauth.AAuthTokenManager(session);
        return tokenManager.calculateAgentJkt(agentPublicKey);
    }

    private String buildPendingPath() {
        try {
            String base = session.getContext().getUri().getBaseUri().toString();
            // Remove trailing slash
            if (base.endsWith("/")) base = base.substring(0, base.length() - 1);
            return base + "/realms/" + realm.getName() + "/protocol/aauth/pending/" + pendingId;
        } catch (Exception e) {
            return "/realms/" + realm.getName() + "/protocol/aauth/pending/" + pendingId;
        }
    }

    private String buildAAuthHeader(AAuthPendingRequest pending) {
        if (AAuthPendingRequest.REQUIRE_INTERACTION.equals(pending.getRequireType())
                && pending.getInteractionCode() != null) {
            return "require=interaction; code=\"" + pending.getInteractionCode() + "\"";
        } else if (AAuthPendingRequest.REQUIRE_APPROVAL.equals(pending.getRequireType())) {
            return "require=approval";
        }
        return "require=" + pending.getRequireType();
    }
}
