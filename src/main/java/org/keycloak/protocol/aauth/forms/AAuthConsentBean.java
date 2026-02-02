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
 * Provides agent, resource, and scope information to the consent screen.
 * Similar to OAuthGrantBean but for AAuth protocol (no dependency on ClientScopeModel).
 */
public class AAuthConsentBean {

    private final String consentCode;
    private final String agentId;
    private final String resourceId;
    private final List<String> scopes;
    private final String consentActionUrl;

    public AAuthConsentBean(String consentCode, String agentId, String resourceId,
                           List<String> scopes, String consentActionUrl) {
        this.consentCode = consentCode;
        this.agentId = agentId;
        this.resourceId = resourceId;
        this.scopes = scopes;
        this.consentActionUrl = consentActionUrl;
    }

    public String getConsentCode() {
        return consentCode;
    }

    public String getAgentId() {
        return agentId;
    }

    public String getResourceId() {
        return resourceId;
    }

    public List<String> getScopes() {
        return scopes;
    }

    public String getConsentActionUrl() {
        return consentActionUrl;
    }
}
