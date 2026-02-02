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

import org.jboss.logging.Logger;
import org.keycloak.connections.httpclient.HttpClientProvider;
import org.keycloak.jose.jwk.JSONWebKeySet;
import org.keycloak.models.KeycloakSession;
import org.keycloak.util.JsonSerialization;

import java.net.URI;
import java.net.URISyntaxException;

/**
 * Fetches metadata documents from agents and resources.
 * 
 * Handles fetching:
 * - Agent metadata from /.well-known/aauth-agent
 * - Resource metadata from /.well-known/aauth-resource
 * - JWKS from jwks_uri endpoints
 */
public class MetadataFetcher {

    private static final Logger logger = Logger.getLogger(MetadataFetcher.class);
    private final KeycloakSession session;

    public MetadataFetcher(KeycloakSession session) {
        this.session = session;
    }

    /**
     * Fetch agent metadata from /.well-known/aauth-agent.
     * 
     * @param agentId The agent identifier (HTTPS URL)
     * @param wellKnown The well-known document name (default: "aauth-agent")
     * @return Agent metadata, or null if not found
     */
    public AgentMetadata fetchAgentMetadata(String agentId, String wellKnown) {
        try {
            URI agentUri = new URI(agentId);
            String scheme = agentUri.getScheme();
            String host = agentUri.getHost();
            
            // Allow HTTP for localhost/127.0.0.1 and *.localhost subdomains for testing purposes
            boolean isLocalhost = isLocalhostHost(host);
            if (!"https".equals(scheme) && !(isLocalhost && "http".equals(scheme))) {
                logger.warnf("Agent identifier must use HTTPS (or HTTP for localhost): %s", agentId);
                return null;
            }

            String metadataUrl = buildWellKnownUrl(agentId, wellKnown != null ? wellKnown : "aauth-agent");
            logger.debugf("Fetching agent metadata from: %s", metadataUrl);

            HttpClientProvider httpClient = session.getProvider(HttpClientProvider.class);
            String metadataJson = httpClient.getString(metadataUrl);

            if (metadataJson == null || metadataJson.trim().isEmpty()) {
                logger.warnf("Empty response from agent metadata endpoint: %s", metadataUrl);
                return null;
            }

            AgentMetadata metadata = JsonSerialization.readValue(metadataJson, AgentMetadata.class);
            
            // Validate that the agent identifier matches
            if (!agentId.equals(metadata.getAgent())) {
                logger.warnf("Agent identifier mismatch: expected %s, got %s", agentId, metadata.getAgent());
                return null;
            }

            return metadata;

        } catch (URISyntaxException e) {
            logger.warnf(e, "Invalid agent identifier: %s", agentId);
            return null;
        } catch (Exception e) {
            logger.warnf(e, "Failed to fetch agent metadata from: %s", agentId);
            return null;
        }
    }

    /**
     * Fetch resource metadata from /.well-known/aauth-resource.
     * 
     * @param resourceId The resource identifier (HTTPS URL)
     * @return Resource metadata, or null if not found
     */
    public ResourceMetadata fetchResourceMetadata(String resourceId) {
        try {
            URI resourceUri = new URI(resourceId);
            String scheme = resourceUri.getScheme();
            String host = resourceUri.getHost();
            
            // Allow HTTP for localhost/127.0.0.1 and *.localhost subdomains for testing purposes
            boolean isLocalhost = isLocalhostHost(host);
            if (!"https".equals(scheme) && !(isLocalhost && "http".equals(scheme))) {
                logger.warnf("Resource identifier must use HTTPS (or HTTP for localhost): %s", resourceId);
                return null;
            }

            String metadataUrl = buildWellKnownUrl(resourceId, "aauth-resource");
            logger.debugf("Fetching resource metadata from: %s", metadataUrl);

            HttpClientProvider httpClient = session.getProvider(HttpClientProvider.class);
            String metadataJson = httpClient.getString(metadataUrl);

            if (metadataJson == null || metadataJson.trim().isEmpty()) {
                logger.warnf("Empty response from resource metadata endpoint: %s", metadataUrl);
                return null;
            }

            ResourceMetadata metadata = JsonSerialization.readValue(metadataJson, ResourceMetadata.class);
            
            // Validate that the resource identifier matches
            if (!resourceId.equals(metadata.getResource())) {
                logger.warnf("Resource identifier mismatch: expected %s, got %s", resourceId, metadata.getResource());
                return null;
            }

            return metadata;

        } catch (URISyntaxException e) {
            logger.warnf(e, "Invalid resource identifier: %s", resourceId);
            return null;
        } catch (Exception e) {
            logger.warnf(e, "Failed to fetch resource metadata from: %s", resourceId);
            return null;
        }
    }

    /**
     * Fetch JWKS from a jwks_uri.
     * 
     * @param jwksUri The JWKS URI
     * @return JSONWebKeySet, or null if not found
     */
    public JSONWebKeySet fetchJWKS(String jwksUri) {
        try {
            URI uri = new URI(jwksUri);
            String scheme = uri.getScheme();
            String host = uri.getHost();
            
            // Allow HTTP for localhost/127.0.0.1 and *.localhost subdomains for testing purposes
            boolean isLocalhost = isLocalhostHost(host);
            if (!"https".equals(scheme) && !(isLocalhost && "http".equals(scheme))) {
                logger.warnf("JWKS URI must use HTTPS (or HTTP for localhost): %s", jwksUri);
                return null;
            }

            logger.debugf("Fetching JWKS from: %s", jwksUri);

            HttpClientProvider httpClient = session.getProvider(HttpClientProvider.class);
            String jwksJson = httpClient.getString(jwksUri);

            if (jwksJson == null || jwksJson.trim().isEmpty()) {
                logger.warnf("Empty response from JWKS endpoint: %s", jwksUri);
                return null;
            }

            return JsonSerialization.readValue(jwksJson, JSONWebKeySet.class);

        } catch (URISyntaxException e) {
            logger.warnf(e, "Invalid JWKS URI: %s", jwksUri);
            return null;
        } catch (Exception e) {
            logger.warnf(e, "Failed to fetch JWKS from: %s", jwksUri);
            return null;
        }
    }

    /**
     * Check if a host is localhost or a localhost subdomain.
     * Allows: localhost, 127.0.0.1, [::1], *.localhost
     */
    private boolean isLocalhostHost(String host) {
        if (host == null) {
            return false;
        }
        // Exact matches
        if (host.equals("localhost") || host.equals("127.0.0.1") || host.equals("[::1]")) {
            return true;
        }
        // Subdomains of localhost (e.g., backend.localhost)
        return host.endsWith(".localhost") || host.endsWith(".localhost.");
    }

    /**
     * Build a well-known URL from a base URL and document name.
     */
    private String buildWellKnownUrl(String baseUrl, String documentName) {
        // Ensure base URL doesn't end with /
        if (baseUrl.endsWith("/")) {
            baseUrl = baseUrl.substring(0, baseUrl.length() - 1);
        }
        return baseUrl + "/.well-known/" + documentName;
    }
}

