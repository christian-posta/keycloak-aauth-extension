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

package org.keycloak.protocol.aauth.storage;

import org.jboss.logging.Logger;
import org.keycloak.common.util.Time;
import org.keycloak.models.KeycloakSession;
import org.keycloak.models.SingleUseObjectProvider;

import java.security.SecureRandom;
import java.util.Map;
import java.util.UUID;

/**
 * Manages lifecycle of pending authorization requests.
 *
 * Uses SingleUseObjectProvider for storage:
 *   Key "aauth.pending.{id}"   → pending request data
 *   Key "aauth.icode.{code}"   → interaction code → pending id mapping
 *
 * Because SingleUseObjectProvider supports get-without-consume, we can
 * poll the same pending request repeatedly. Updates are done by
 * remove-then-put with the remaining TTL.
 */
public class AAuthPendingRequestStore {

    private static final Logger logger = Logger.getLogger(AAuthPendingRequestStore.class);
    private static final int DEFAULT_LIFESPAN = 600; // 10 minutes
    private static final String PENDING_PREFIX = "aauth.pending.";
    private static final String ICODE_PREFIX = "aauth.icode.";

    private static final String CHARS = "ABCDEFGHJKLMNPQRSTUVWXYZ23456789"; // no I/O/0/1 to avoid confusion
    private static final int CODE_LENGTH = 8;
    private static final SecureRandom RANDOM = new SecureRandom();

    private final KeycloakSession session;

    public AAuthPendingRequestStore(KeycloakSession session) {
        this.session = session;
    }

    /**
     * Create a new pending request and persist it.
     *
     * @return The created AAuthPendingRequest (with id and interactionCode populated)
     */
    public AAuthPendingRequest createPendingRequest(String agentId, String agentJkt,
            String signatureScheme, String resourceId, String scope, String purpose,
            String requireType, String callbackUrl) {
        return createPendingRequest(agentId, agentJkt, signatureScheme, resourceId, scope, purpose,
                requireType, callbackUrl, false);
    }

    /**
     * Create a new pending request with optional clarification mode enabled.
     */
    public AAuthPendingRequest createPendingRequest(String agentId, String agentJkt,
            String signatureScheme, String resourceId, String scope, String purpose,
            String requireType, String callbackUrl, boolean clarificationEnabled) {

        String id = UUID.randomUUID().toString();
        int now = Time.currentTime();
        int expiresAt = now + DEFAULT_LIFESPAN;
        String interactionCode = requireType.equals(AAuthPendingRequest.REQUIRE_INTERACTION)
                ? generateInteractionCode() : null;

        AAuthPendingRequest pending = new AAuthPendingRequest(
                id, expiresAt, agentId, agentJkt, signatureScheme, resourceId, scope,
                purpose, requireType, interactionCode, callbackUrl, now);
        pending.setClarificationEnabled(clarificationEnabled);

        SingleUseObjectProvider store = session.singleUseObjects();
        store.put(PENDING_PREFIX + id, DEFAULT_LIFESPAN, pending.serialize());

        // Store interaction code → id mapping
        if (interactionCode != null) {
            Map<String, String> codeMap = java.util.Map.of("pending_id", id);
            store.put(ICODE_PREFIX + interactionCode, DEFAULT_LIFESPAN, codeMap);
        }

        logger.debugf("Created pending request id=%s, code=%s, agent=%s, resource=%s",
                id, interactionCode, agentId, resourceId);
        return pending;
    }

    /**
     * Retrieve a pending request by its ID without consuming it.
     */
    public AAuthPendingRequest getPendingRequest(String id) {
        if (id == null || id.isEmpty()) return null;
        Map<String, String> data = session.singleUseObjects().get(PENDING_PREFIX + id);
        if (data == null) return null;
        AAuthPendingRequest req = AAuthPendingRequest.deserialize(data);
        // Check expiration
        if (Time.currentTime() > req.getExpiresAt()) {
            session.singleUseObjects().remove(PENDING_PREFIX + id);
            return null;
        }
        return req;
    }

    /**
     * Retrieve a pending request by its interaction code (for the interaction endpoint).
     */
    public AAuthPendingRequest getByInteractionCode(String code) {
        if (code == null || code.isEmpty()) return null;
        Map<String, String> codeMap = session.singleUseObjects().get(ICODE_PREFIX + code);
        if (codeMap == null) return null;
        String id = codeMap.get("pending_id");
        return getPendingRequest(id);
    }

    /**
     * Update a pending request in place (remove + re-put with remaining TTL).
     */
    public void updatePendingRequest(AAuthPendingRequest req) {
        String key = PENDING_PREFIX + req.getId();
        session.singleUseObjects().remove(key);
        int remaining = req.getExpiresAt() - Time.currentTime();
        if (remaining <= 0) {
            logger.debugf("Pending request expired, not re-storing: id=%s", req.getId());
            return;
        }
        session.singleUseObjects().put(key, remaining, req.serialize());
    }

    /**
     * Mark a pending request as completed with the given auth token.
     */
    public void completePendingRequest(String id, String authToken, long expiresIn) {
        AAuthPendingRequest req = getPendingRequest(id);
        if (req == null) {
            logger.warnf("Cannot complete pending request - not found: id=%s", id);
            return;
        }
        req.setStatus(AAuthPendingRequest.STATUS_COMPLETED);
        req.setAuthToken(authToken);
        req.setExpiresIn(expiresIn);
        updatePendingRequest(req);
        logger.debugf("Completed pending request id=%s", id);
    }

    /**
     * Mark a pending request as denied.
     */
    public void denyPendingRequest(String id, String error, String errorDescription) {
        AAuthPendingRequest req = getPendingRequest(id);
        if (req == null) return;
        req.setStatus(AAuthPendingRequest.STATUS_DENIED);
        req.setError(error);
        req.setErrorDescription(errorDescription);
        updatePendingRequest(req);
        logger.debugf("Denied pending request id=%s, error=%s", id, error);
    }

    /**
     * Store a clarification question from the user, changing status to awaiting_clarification.
     */
    public void setClarificationQuestion(String id, String question) {
        AAuthPendingRequest req = getPendingRequest(id);
        if (req == null) return;
        req.setClarification(question);
        req.setStatus(AAuthPendingRequest.STATUS_AWAITING_CLARIFICATION);
        updatePendingRequest(req);
        logger.debugf("Set clarification question for pending request id=%s", id);
    }

    /**
     * Store an agent's clarification response, changing status back to pending.
     */
    public void setClarificationResponse(String id, String response) {
        AAuthPendingRequest req = getPendingRequest(id);
        if (req == null) return;
        req.setClarificationResponse(response);
        req.setStatus(AAuthPendingRequest.STATUS_PENDING);
        updatePendingRequest(req);
        logger.debugf("Set clarification response for pending request id=%s", id);
    }

    /**
     * Consume (remove) a pending request after delivering terminal response.
     */
    public AAuthPendingRequest consumePendingRequest(String id) {
        Map<String, String> data = session.singleUseObjects().remove(PENDING_PREFIX + id);
        if (data == null) return null;
        return AAuthPendingRequest.deserialize(data);
    }

    /**
     * Generate a short, human-friendly interaction code (e.g., "ABCD1234").
     * Uses uppercase letters and digits, avoiding easily-confused chars.
     */
    private String generateInteractionCode() {
        StringBuilder sb = new StringBuilder(CODE_LENGTH);
        for (int i = 0; i < CODE_LENGTH; i++) {
            sb.append(CHARS.charAt(RANDOM.nextInt(CHARS.length())));
        }
        return sb.toString();
    }
}
