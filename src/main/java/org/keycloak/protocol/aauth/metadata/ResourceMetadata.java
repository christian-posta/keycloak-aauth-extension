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

import java.util.List;
import java.util.Map;

/**
 * Resource metadata document per SPEC_UPDATED.md Section 13.3.
 * Published at /.well-known/aauth-resource.json
 */
@JsonIgnoreProperties(ignoreUnknown = true)
public class ResourceMetadata {

    @JsonProperty("resource")
    private String resource;

    @JsonProperty("jwks_uri")
    private String jwksUri;

    @JsonProperty("client_name")
    private String clientName;

    @JsonProperty("logo_uri")
    private String logoUri;

    @JsonProperty("logo_dark_uri")
    private String logoDarkUri;

    @JsonProperty("resource_token_endpoint")
    private String resourceTokenEndpoint;

    @JsonProperty("interaction_endpoint")
    private String interactionEndpoint;

    @JsonProperty("scope_descriptions")
    private Map<String, String> scopeDescriptions;

    @JsonProperty("additional_signature_components")
    private List<String> additionalSignatureComponents;

    public String getResource() { return resource; }
    public void setResource(String resource) { this.resource = resource; }

    public String getJwksUri() { return jwksUri; }
    public void setJwksUri(String jwksUri) { this.jwksUri = jwksUri; }

    public String getClientName() { return clientName; }
    public void setClientName(String clientName) { this.clientName = clientName; }

    public String getLogoUri() { return logoUri; }
    public void setLogoUri(String logoUri) { this.logoUri = logoUri; }

    public String getLogoDarkUri() { return logoDarkUri; }
    public void setLogoDarkUri(String logoDarkUri) { this.logoDarkUri = logoDarkUri; }

    public String getResourceTokenEndpoint() { return resourceTokenEndpoint; }
    public void setResourceTokenEndpoint(String resourceTokenEndpoint) { this.resourceTokenEndpoint = resourceTokenEndpoint; }

    public String getInteractionEndpoint() { return interactionEndpoint; }
    public void setInteractionEndpoint(String interactionEndpoint) { this.interactionEndpoint = interactionEndpoint; }

    public Map<String, String> getScopeDescriptions() { return scopeDescriptions; }
    public void setScopeDescriptions(Map<String, String> scopeDescriptions) { this.scopeDescriptions = scopeDescriptions; }

    public List<String> getAdditionalSignatureComponents() { return additionalSignatureComponents; }
    public void setAdditionalSignatureComponents(List<String> additionalSignatureComponents) { this.additionalSignatureComponents = additionalSignatureComponents; }
}
