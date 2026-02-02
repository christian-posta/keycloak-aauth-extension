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

package org.keycloak.protocol.aauth.policy;

import org.jboss.logging.Logger;
import org.keycloak.models.KeycloakSession;
import org.keycloak.models.RealmModel;
import org.keycloak.protocol.aauth.AAuthConfig;

/**
 * Default implementation of AAuthPolicyEvaluator using realm attributes.
 * 
 * This implementation reads policy configuration from realm attributes,
 * providing simple allow/block list functionality. For more sophisticated
 * policy evaluation, a custom implementation can integrate with
 * Keycloak's Authorization Services.
 */
public class DefaultAAuthPolicyEvaluator implements AAuthPolicyEvaluator {

    private static final Logger logger = Logger.getLogger(DefaultAAuthPolicyEvaluator.class);

    // Session stored for future Authorization Services integration
    @SuppressWarnings("unused")
    private final KeycloakSession session;

    public DefaultAAuthPolicyEvaluator(KeycloakSession session) {
        this.session = session;
    }

    @Override
    public boolean isProtocolEnabled(RealmModel realm) {
        AAuthConfig config = AAuthConfig.forRealm(realm);
        return config.isEnabled();
    }

    @Override
    public boolean isAgentAllowed(String agentId, RealmModel realm) {
        if (agentId == null) {
            logger.debug("Agent ID is null, denying");
            return false;
        }

        AAuthConfig config = AAuthConfig.forRealm(realm);
        boolean allowed = config.isAgentAllowed(agentId);
        
        if (!allowed) {
            logger.debugf("Agent '%s' is not allowed by policy", agentId);
        }
        
        return allowed;
    }

    @Override
    public boolean isScopeAllowed(String scope, RealmModel realm) {
        if (scope == null) {
            return true; // No scope requested
        }

        AAuthConfig config = AAuthConfig.forRealm(realm);
        return config.isScopeAllowed(scope);
    }

    @Override
    public boolean areScopesAllowed(String scopeString, RealmModel realm) {
        if (scopeString == null || scopeString.isEmpty()) {
            return true;
        }

        AAuthConfig config = AAuthConfig.forRealm(realm);
        boolean allowed = config.areScopesAllowed(scopeString);
        
        if (!allowed) {
            logger.debugf("One or more scopes in '%s' are not allowed by policy", scopeString);
        }
        
        return allowed;
    }

    @Override
    public boolean isAgentScopeAllowed(String agentId, String scopeString, RealmModel realm) {
        // Default implementation: check agent and scopes independently
        // Future implementations can add agent-specific scope restrictions
        return isAgentAllowed(agentId, realm) && areScopesAllowed(scopeString, realm);
    }

    @Override
    public boolean isExchangeEnabled(RealmModel realm) {
        AAuthConfig config = AAuthConfig.forRealm(realm);
        return config.isExchangeEnabled();
    }

    @Override
    public boolean isIssuerTrusted(String upstreamIssuer, String currentRealmIssuer, RealmModel realm) {
        if (upstreamIssuer == null) {
            logger.debug("Upstream issuer is null, denying");
            return false;
        }

        // Same-server issuer is always trusted
        if (upstreamIssuer.equals(currentRealmIssuer)) {
            return true;
        }

        AAuthConfig config = AAuthConfig.forRealm(realm);
        boolean trusted = config.getTrustedIssuers().contains(upstreamIssuer);
        
        if (!trusted) {
            logger.debugf("Upstream issuer '%s' is not trusted", upstreamIssuer);
        }
        
        return trusted;
    }

    @Override
    public boolean isExchangeAllowed(String upstreamIssuer, String agentId, String requestedScopes,
                                     String currentRealmIssuer, RealmModel realm) {
        // Check if exchange is enabled
        if (!isExchangeEnabled(realm)) {
            logger.debug("Token exchange is disabled for this realm");
            return false;
        }

        // Check if upstream issuer is trusted
        if (!isIssuerTrusted(upstreamIssuer, currentRealmIssuer, realm)) {
            return false;
        }

        // Check if agent is allowed
        if (!isAgentAllowed(agentId, realm)) {
            return false;
        }

        // Check if scopes are allowed
        if (!areScopesAllowed(requestedScopes, realm)) {
            return false;
        }

        return true;
    }

    @Override
    public int getMaxDelegationDepth(RealmModel realm) {
        AAuthConfig config = AAuthConfig.forRealm(realm);
        return config.getExchangeMaxDepth();
    }

    @Override
    public int getTokenLifespan(RealmModel realm) {
        AAuthConfig config = AAuthConfig.forRealm(realm);
        return config.getTokenLifespan();
    }

    @Override
    public int getRefreshTokenLifespan(RealmModel realm) {
        AAuthConfig config = AAuthConfig.forRealm(realm);
        return config.getRefreshLifespan();
    }

    /**
     * Factory method for creating the default policy evaluator.
     */
    public static DefaultAAuthPolicyEvaluator create(KeycloakSession session) {
        return new DefaultAAuthPolicyEvaluator(session);
    }
}

