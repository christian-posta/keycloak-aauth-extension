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

package org.keycloak.protocol.aauth;

import org.keycloak.models.RealmModel;
import org.keycloak.util.JsonSerialization;

import java.io.IOException;
import java.util.Collections;
import java.util.List;

/**
 * Configuration settings for the AAuth protocol.
 * 
 * Reads configuration from realm attributes, providing a centralized
 * way to access AAuth settings throughout the codebase.
 */
public class AAuthConfig {

    // Realm attribute keys
    public static final String ENABLED = "aauth.enabled";
    public static final String TRUSTED_ISSUERS = "aauth.trusted.issuers";
    public static final String ALLOWED_AGENTS = "aauth.allowed.agents";
    public static final String BLOCKED_AGENTS = "aauth.blocked.agents";
    public static final String ALLOWED_SCOPES = "aauth.allowed.scopes";
    public static final String TOKEN_LIFESPAN = "aauth.token.lifespan";
    public static final String REFRESH_LIFESPAN = "aauth.refresh.lifespan";
    public static final String EXCHANGE_ENABLED = "aauth.exchange.enabled";
    public static final String EXCHANGE_MAX_DEPTH = "aauth.exchange.max.depth";

    // Default values
    public static final int DEFAULT_TOKEN_LIFESPAN = 300; // 5 minutes
    public static final int DEFAULT_REFRESH_LIFESPAN = 1800; // 30 minutes
    public static final int DEFAULT_EXCHANGE_MAX_DEPTH = 10;

    private final RealmModel realm;

    public AAuthConfig(RealmModel realm) {
        this.realm = realm;
    }

    /**
     * Check if AAuth protocol is enabled for this realm.
     * Defaults to true if not explicitly set.
     */
    public boolean isEnabled() {
        String value = realm.getAttribute(ENABLED);
        return value == null || Boolean.parseBoolean(value);
    }

    /**
     * Get list of trusted auth server issuers for token exchange.
     * Empty list means no external issuers are trusted (only same-server exchange).
     */
    public List<String> getTrustedIssuers() {
        return getJsonListAttribute(TRUSTED_ISSUERS);
    }

    /**
     * Get list of allowed agent identifiers.
     * Empty list means all agents are allowed (no allowlist).
     */
    public List<String> getAllowedAgents() {
        return getJsonListAttribute(ALLOWED_AGENTS);
    }

    /**
     * Get list of blocked agent identifiers.
     * Empty list means no agents are blocked.
     */
    public List<String> getBlockedAgents() {
        return getJsonListAttribute(BLOCKED_AGENTS);
    }

    /**
     * Get list of allowed scopes that agents can request.
     * Empty list means all scopes are allowed.
     */
    public List<String> getAllowedScopes() {
        return getJsonListAttribute(ALLOWED_SCOPES);
    }

    /**
     * Get auth token lifespan in seconds.
     */
    public int getTokenLifespan() {
        return getIntAttribute(TOKEN_LIFESPAN, DEFAULT_TOKEN_LIFESPAN);
    }

    /**
     * Get refresh token lifespan in seconds.
     */
    public int getRefreshLifespan() {
        return getIntAttribute(REFRESH_LIFESPAN, DEFAULT_REFRESH_LIFESPAN);
    }

    /**
     * Check if token exchange is enabled.
     * Defaults to true.
     */
    public boolean isExchangeEnabled() {
        String value = realm.getAttribute(EXCHANGE_ENABLED);
        return value == null || Boolean.parseBoolean(value);
    }

    /**
     * Get maximum delegation chain depth for token exchange.
     */
    public int getExchangeMaxDepth() {
        return getIntAttribute(EXCHANGE_MAX_DEPTH, DEFAULT_EXCHANGE_MAX_DEPTH);
    }

    /**
     * Check if a specific issuer is trusted for token exchange.
     * Same-realm issuer is always trusted.
     */
    public boolean isIssuerTrusted(String issuer) {
        if (issuer == null) {
            return false;
        }
        
        // Same-server issuer is always trusted
        String realmIssuer = getRealmIssuer();
        if (issuer.equals(realmIssuer)) {
            return true;
        }
        
        // Check trusted issuers list
        List<String> trustedIssuers = getTrustedIssuers();
        return trustedIssuers.contains(issuer);
    }

    /**
     * Check if an agent is allowed based on allow/block lists.
     * 
     * Logic:
     * 1. If agent is in blocked list, deny
     * 2. If allowlist is empty, allow all (not blocked)
     * 3. If allowlist is non-empty, agent must be in it
     */
    public boolean isAgentAllowed(String agentId) {
        if (agentId == null) {
            return false;
        }
        
        // Check blocklist first
        List<String> blockedAgents = getBlockedAgents();
        if (blockedAgents.contains(agentId)) {
            return false;
        }
        
        // Check allowlist
        List<String> allowedAgents = getAllowedAgents();
        if (allowedAgents.isEmpty()) {
            // No allowlist = allow all (except blocked)
            return true;
        }
        
        return allowedAgents.contains(agentId);
    }

    /**
     * Check if a scope is allowed for agents to request.
     */
    public boolean isScopeAllowed(String scope) {
        if (scope == null) {
            return false;
        }
        
        List<String> allowedScopes = getAllowedScopes();
        if (allowedScopes.isEmpty()) {
            // No scope restriction
            return true;
        }
        
        return allowedScopes.contains(scope);
    }

    /**
     * Check if all requested scopes are allowed.
     */
    public boolean areScopesAllowed(String scopeString) {
        if (scopeString == null || scopeString.isEmpty()) {
            return true;
        }
        
        List<String> allowedScopes = getAllowedScopes();
        if (allowedScopes.isEmpty()) {
            return true;
        }
        
        String[] scopes = scopeString.split("\\s+");
        for (String scope : scopes) {
            if (!allowedScopes.contains(scope)) {
                return false;
            }
        }
        return true;
    }

    /**
     * Get the realm issuer URL.
     */
    private String getRealmIssuer() {
        // This matches how Keycloak generates issuer URLs
        // The actual implementation may need to use Urls.realmIssuer() if available
        return null; // Will be set by caller who has access to URI info
    }

    /**
     * Parse a JSON array attribute into a list of strings.
     */
    @SuppressWarnings("unchecked")
    private List<String> getJsonListAttribute(String key) {
        String value = realm.getAttribute(key);
        if (value == null || value.isEmpty()) {
            return Collections.emptyList();
        }
        
        try {
            return JsonSerialization.readValue(value, List.class);
        } catch (IOException e) {
            // Invalid JSON, return empty list
            return Collections.emptyList();
        }
    }

    /**
     * Get an integer attribute with a default value.
     */
    private int getIntAttribute(String key, int defaultValue) {
        String value = realm.getAttribute(key);
        if (value == null || value.isEmpty()) {
            return defaultValue;
        }
        
        try {
            return Integer.parseInt(value);
        } catch (NumberFormatException e) {
            return defaultValue;
        }
    }

    /**
     * Static factory method for convenience.
     */
    public static AAuthConfig forRealm(RealmModel realm) {
        return new AAuthConfig(realm);
    }
}

