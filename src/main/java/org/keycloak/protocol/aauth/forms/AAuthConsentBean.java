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

package org.keycloak.protocol.aauth.forms;

import java.util.List;

/**
 * Data bean for AAuth consent page template.
 *
 * Provides agent, resource, scope, and clarification information to the consent screen.
 */
public class AAuthConsentBean {

    private final String consentCode;
    private final String agentId;
    private final String resourceId;
    private final List<String> scopes;
    private final String consentActionUrl;

    // Clarification chat fields
    private boolean clarificationEnabled;
    private String clarification;
    private String clarificationResponse;
    private String pendingRequestId;
    private String interactionCode;
    private String callbackUrl;
    private String state;
    private String clarifyActionUrl;

    public AAuthConsentBean(String consentCode, String agentId, String resourceId,
                           List<String> scopes, String consentActionUrl) {
        this.consentCode = consentCode;
        this.agentId = agentId;
        this.resourceId = resourceId;
        this.scopes = scopes;
        this.consentActionUrl = consentActionUrl;
    }

    public String getConsentCode() { return consentCode; }
    public String getAgentId() { return agentId; }
    public String getResourceId() { return resourceId; }
    public List<String> getScopes() { return scopes; }
    public String getConsentActionUrl() { return consentActionUrl; }

    public boolean isClarificationEnabled() { return clarificationEnabled; }
    public void setClarificationEnabled(boolean clarificationEnabled) { this.clarificationEnabled = clarificationEnabled; }

    public String getClarification() { return clarification; }
    public void setClarification(String clarification) { this.clarification = clarification; }

    public String getClarificationResponse() { return clarificationResponse; }
    public void setClarificationResponse(String clarificationResponse) { this.clarificationResponse = clarificationResponse; }

    /** True if clarification question has been sent but agent hasn't replied yet. */
    public boolean isAwaitingResponse() {
        return clarificationEnabled && clarification != null && clarificationResponse == null;
    }

    public String getPendingRequestId() { return pendingRequestId; }
    public void setPendingRequestId(String pendingRequestId) { this.pendingRequestId = pendingRequestId; }

    public String getInteractionCode() { return interactionCode; }
    public void setInteractionCode(String interactionCode) { this.interactionCode = interactionCode; }

    public String getCallbackUrl() { return callbackUrl; }
    public void setCallbackUrl(String callbackUrl) { this.callbackUrl = callbackUrl; }

    public String getState() { return state; }
    public void setState(String state) { this.state = state; }

    public String getClarifyActionUrl() { return clarifyActionUrl; }
    public void setClarifyActionUrl(String clarifyActionUrl) { this.clarifyActionUrl = clarifyActionUrl; }

    /** URL to reload the consent screen (used for "Check for response" link in waiting state). */
    private String refreshUrl;
    public String getRefreshUrl() { return refreshUrl; }
    public void setRefreshUrl(String refreshUrl) { this.refreshUrl = refreshUrl; }
}
