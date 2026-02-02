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

import com.fasterxml.jackson.annotation.JsonProperty;

import java.util.List;
import java.util.Map;

/**
 * Resource metadata document per AAuth specification Section 8.3.
 */
public class ResourceMetadata {

    @JsonProperty("resource")
    private String resource;

    @JsonProperty("jwks_uri")
    private String jwksUri;

    @JsonProperty("resource_token_endpoint")
    private String resourceTokenEndpoint;

    @JsonProperty("supported_scopes")
    private List<String> supportedScopes;

    @JsonProperty("scope_descriptions")
    private Map<String, String> scopeDescriptions;

    public String getResource() {
        return resource;
    }

    public void setResource(String resource) {
        this.resource = resource;
    }

    public String getJwksUri() {
        return jwksUri;
    }

    public void setJwksUri(String jwksUri) {
        this.jwksUri = jwksUri;
    }

    public String getResourceTokenEndpoint() {
        return resourceTokenEndpoint;
    }

    public void setResourceTokenEndpoint(String resourceTokenEndpoint) {
        this.resourceTokenEndpoint = resourceTokenEndpoint;
    }

    public List<String> getSupportedScopes() {
        return supportedScopes;
    }

    public void setSupportedScopes(List<String> supportedScopes) {
        this.supportedScopes = supportedScopes;
    }

    public Map<String, String> getScopeDescriptions() {
        return scopeDescriptions;
    }

    public void setScopeDescriptions(Map<String, String> scopeDescriptions) {
        this.scopeDescriptions = scopeDescriptions;
    }
}

