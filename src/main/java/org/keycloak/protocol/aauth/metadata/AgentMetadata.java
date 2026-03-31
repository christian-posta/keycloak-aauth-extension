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

package org.keycloak.protocol.aauth.metadata;

import com.fasterxml.jackson.annotation.JsonIgnoreProperties;
import com.fasterxml.jackson.annotation.JsonProperty;

/**
 * Agent server metadata document per SPEC_UPDATED.md Section 13.1.
 * Published at /.well-known/aauth-agent.json
 */
@JsonIgnoreProperties(ignoreUnknown = true)
public class AgentMetadata {

    @JsonProperty("agent")
    private String agent;

    @JsonProperty("jwks_uri")
    private String jwksUri;

    @JsonProperty("client_name")
    private String clientName;

    @JsonProperty("logo_uri")
    private String logoUri;

    @JsonProperty("logo_dark_uri")
    private String logoDarkUri;

    @JsonProperty("callback_endpoint")
    private String callbackEndpoint;

    @JsonProperty("localhost_callback_allowed")
    private Boolean localhostCallbackAllowed;

    @JsonProperty("clarification_supported")
    private Boolean clarificationSupported;

    @JsonProperty("tos_uri")
    private String tosUri;

    @JsonProperty("policy_uri")
    private String policyUri;

    public String getAgent() { return agent; }
    public void setAgent(String agent) { this.agent = agent; }

    public String getJwksUri() { return jwksUri; }
    public void setJwksUri(String jwksUri) { this.jwksUri = jwksUri; }

    public String getClientName() { return clientName; }
    public void setClientName(String clientName) { this.clientName = clientName; }

    public String getLogoUri() { return logoUri; }
    public void setLogoUri(String logoUri) { this.logoUri = logoUri; }

    public String getLogoDarkUri() { return logoDarkUri; }
    public void setLogoDarkUri(String logoDarkUri) { this.logoDarkUri = logoDarkUri; }

    public String getCallbackEndpoint() { return callbackEndpoint; }
    public void setCallbackEndpoint(String callbackEndpoint) { this.callbackEndpoint = callbackEndpoint; }

    public Boolean getLocalhostCallbackAllowed() { return localhostCallbackAllowed; }
    public void setLocalhostCallbackAllowed(Boolean localhostCallbackAllowed) { this.localhostCallbackAllowed = localhostCallbackAllowed; }

    public Boolean getClarificationSupported() { return clarificationSupported; }
    public void setClarificationSupported(Boolean clarificationSupported) { this.clarificationSupported = clarificationSupported; }

    public String getTosUri() { return tosUri; }
    public void setTosUri(String tosUri) { this.tosUri = tosUri; }

    public String getPolicyUri() { return policyUri; }
    public void setPolicyUri(String policyUri) { this.policyUri = policyUri; }
}
