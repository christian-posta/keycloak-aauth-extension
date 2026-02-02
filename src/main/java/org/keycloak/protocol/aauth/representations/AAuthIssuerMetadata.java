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

package org.keycloak.protocol.aauth.representations;

import com.fasterxml.jackson.annotation.JsonProperty;

import java.util.List;

/**
 * AAuth Issuer Metadata as defined in AAuth specification Section 8.2.
 * 
 * Published at `/.well-known/aauth-issuer` endpoint.
 */
public class AAuthIssuerMetadata {

    @JsonProperty("issuer")
    private String issuer;

    @JsonProperty("jwks_uri")
    private String jwksUri;

    @JsonProperty("agent_token_endpoint")
    private String agentTokenEndpoint;

    @JsonProperty("agent_auth_endpoint")
    private String agentAuthEndpoint;

    @JsonProperty("agent_signing_algs_supported")
    private List<String> agentSigningAlgsSupported;

    @JsonProperty("request_types_supported")
    private List<String> requestTypesSupported;

    @JsonProperty("scopes_supported")
    private List<String> scopesSupported;

    public String getIssuer() {
        return issuer;
    }

    public void setIssuer(String issuer) {
        this.issuer = issuer;
    }

    public String getJwksUri() {
        return jwksUri;
    }

    public void setJwksUri(String jwksUri) {
        this.jwksUri = jwksUri;
    }

    public String getAgentTokenEndpoint() {
        return agentTokenEndpoint;
    }

    public void setAgentTokenEndpoint(String agentTokenEndpoint) {
        this.agentTokenEndpoint = agentTokenEndpoint;
    }

    public String getAgentAuthEndpoint() {
        return agentAuthEndpoint;
    }

    public void setAgentAuthEndpoint(String agentAuthEndpoint) {
        this.agentAuthEndpoint = agentAuthEndpoint;
    }

    public List<String> getAgentSigningAlgsSupported() {
        return agentSigningAlgsSupported;
    }

    public void setAgentSigningAlgsSupported(List<String> agentSigningAlgsSupported) {
        this.agentSigningAlgsSupported = agentSigningAlgsSupported;
    }

    public List<String> getRequestTypesSupported() {
        return requestTypesSupported;
    }

    public void setRequestTypesSupported(List<String> requestTypesSupported) {
        this.requestTypesSupported = requestTypesSupported;
    }

    public List<String> getScopesSupported() {
        return scopesSupported;
    }

    public void setScopesSupported(List<String> scopesSupported) {
        this.scopesSupported = scopesSupported;
    }
}
