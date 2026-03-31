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

import java.util.HashMap;
import java.util.Map;

/**
 * Represents a pending authorization request in the 202-deferred flow.
 *
 * A pending request is created when an auth request requires user interaction
 * or approval. The agent polls GET /pending/{id} until the request resolves.
 *
 * Lifecycle:
 *   pending  → completed (user approved, auth_token set)
 *   pending  → denied    (user denied)
 *   pending  → expired   (TTL expired before resolution)
 */
public class AAuthPendingRequest {

    public static final String STATUS_PENDING = "pending";
    public static final String STATUS_COMPLETED = "completed";
    public static final String STATUS_DENIED = "denied";
    public static final String STATUS_EXPIRED = "expired";
    public static final String STATUS_AWAITING_CLARIFICATION = "awaiting_clarification";

    public static final String REQUIRE_INTERACTION = "interaction";
    public static final String REQUIRE_APPROVAL = "approval";

    private String id;
    private String status;
    private String agentId;
    private String agentJkt;
    private String signatureScheme;
    private String resourceId;
    private String scope;
    private String purpose;
    private String requireType;
    private String interactionCode;
    private String callbackUrl;
    private String authToken;
    private long expiresIn;
    private String error;
    private String errorDescription;
    private int createdAt;
    private int expiresAt;
    private boolean clarificationEnabled;
    private String clarification;
    private String clarificationResponse;

    public AAuthPendingRequest() {}

    public AAuthPendingRequest(String id, int expiresAt, String agentId, String agentJkt,
            String signatureScheme, String resourceId, String scope, String purpose,
            String requireType, String interactionCode, String callbackUrl, int createdAt) {
        this.id = id;
        this.expiresAt = expiresAt;
        this.agentId = agentId;
        this.agentJkt = agentJkt;
        this.signatureScheme = signatureScheme;
        this.resourceId = resourceId;
        this.scope = scope;
        this.purpose = purpose;
        this.requireType = requireType;
        this.interactionCode = interactionCode;
        this.callbackUrl = callbackUrl;
        this.createdAt = createdAt;
        this.status = STATUS_PENDING;
    }

    public boolean isPending() {
        return STATUS_PENDING.equals(status);
    }

    public boolean isTerminal() {
        return STATUS_COMPLETED.equals(status) || STATUS_DENIED.equals(status) || STATUS_EXPIRED.equals(status);
    }

    public boolean isClarificationEnabled() { return clarificationEnabled; }
    public void setClarificationEnabled(boolean clarificationEnabled) { this.clarificationEnabled = clarificationEnabled; }

    public String getClarification() { return clarification; }
    public void setClarification(String clarification) { this.clarification = clarification; }

    public String getClarificationResponse() { return clarificationResponse; }
    public void setClarificationResponse(String clarificationResponse) { this.clarificationResponse = clarificationResponse; }

    public Map<String, String> serialize() {
        Map<String, String> map = new HashMap<>();
        map.put("id", id);
        map.put("status", status);
        map.put("expires_at", String.valueOf(expiresAt));
        map.put("created_at", String.valueOf(createdAt));
        if (agentId != null) map.put("agent_id", agentId);
        if (agentJkt != null) map.put("agent_jkt", agentJkt);
        if (signatureScheme != null) map.put("signature_scheme", signatureScheme);
        if (resourceId != null) map.put("resource_id", resourceId);
        if (scope != null) map.put("scope", scope);
        if (purpose != null) map.put("purpose", purpose);
        if (requireType != null) map.put("require_type", requireType);
        if (interactionCode != null) map.put("interaction_code", interactionCode);
        if (callbackUrl != null) map.put("callback_url", callbackUrl);
        if (authToken != null) map.put("auth_token", authToken);
        if (expiresIn > 0) map.put("expires_in", String.valueOf(expiresIn));
        if (error != null) map.put("error", error);
        if (errorDescription != null) map.put("error_description", errorDescription);
        if (clarificationEnabled) map.put("clarification_enabled", "true");
        if (clarification != null) map.put("clarification", clarification);
        if (clarificationResponse != null) map.put("clarification_response", clarificationResponse);
        return map;
    }

    public static AAuthPendingRequest deserialize(Map<String, String> map) {
        AAuthPendingRequest req = new AAuthPendingRequest();
        req.id = map.get("id");
        req.status = map.getOrDefault("status", STATUS_PENDING);
        req.expiresAt = parseInt(map.get("expires_at"), 0);
        req.createdAt = parseInt(map.get("created_at"), 0);
        req.agentId = map.get("agent_id");
        req.agentJkt = map.get("agent_jkt");
        req.signatureScheme = map.get("signature_scheme");
        req.resourceId = map.get("resource_id");
        req.scope = map.get("scope");
        req.purpose = map.get("purpose");
        req.requireType = map.get("require_type");
        req.interactionCode = map.get("interaction_code");
        req.callbackUrl = map.get("callback_url");
        req.authToken = map.get("auth_token");
        req.expiresIn = parseLong(map.get("expires_in"), 0);
        req.error = map.get("error");
        req.errorDescription = map.get("error_description");
        req.clarificationEnabled = "true".equals(map.get("clarification_enabled"));
        req.clarification = map.get("clarification");
        req.clarificationResponse = map.get("clarification_response");
        return req;
    }

    private static int parseInt(String s, int def) {
        if (s == null) return def;
        try { return Integer.parseInt(s); } catch (NumberFormatException e) { return def; }
    }

    private static long parseLong(String s, long def) {
        if (s == null) return def;
        try { return Long.parseLong(s); } catch (NumberFormatException e) { return def; }
    }

    // Getters and setters
    public String getId() { return id; }
    public void setId(String id) { this.id = id; }

    public String getStatus() { return status; }
    public void setStatus(String status) { this.status = status; }

    public String getAgentId() { return agentId; }
    public void setAgentId(String agentId) { this.agentId = agentId; }

    public String getAgentJkt() { return agentJkt; }
    public void setAgentJkt(String agentJkt) { this.agentJkt = agentJkt; }

    public String getSignatureScheme() { return signatureScheme; }
    public void setSignatureScheme(String signatureScheme) { this.signatureScheme = signatureScheme; }

    public String getResourceId() { return resourceId; }
    public void setResourceId(String resourceId) { this.resourceId = resourceId; }

    public String getScope() { return scope; }
    public void setScope(String scope) { this.scope = scope; }

    public String getPurpose() { return purpose; }
    public void setPurpose(String purpose) { this.purpose = purpose; }

    public String getRequireType() { return requireType; }
    public void setRequireType(String requireType) { this.requireType = requireType; }

    public String getInteractionCode() { return interactionCode; }
    public void setInteractionCode(String interactionCode) { this.interactionCode = interactionCode; }

    public String getCallbackUrl() { return callbackUrl; }
    public void setCallbackUrl(String callbackUrl) { this.callbackUrl = callbackUrl; }

    public String getAuthToken() { return authToken; }
    public void setAuthToken(String authToken) { this.authToken = authToken; }

    public long getExpiresIn() { return expiresIn; }
    public void setExpiresIn(long expiresIn) { this.expiresIn = expiresIn; }

    public String getError() { return error; }
    public void setError(String error) { this.error = error; }

    public String getErrorDescription() { return errorDescription; }
    public void setErrorDescription(String errorDescription) { this.errorDescription = errorDescription; }

    public int getCreatedAt() { return createdAt; }
    public void setCreatedAt(int createdAt) { this.createdAt = createdAt; }

    public int getExpiresAt() { return expiresAt; }
    public void setExpiresAt(int expiresAt) { this.expiresAt = expiresAt; }
}
