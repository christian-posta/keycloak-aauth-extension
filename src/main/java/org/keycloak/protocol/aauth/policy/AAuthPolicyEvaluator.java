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

import org.keycloak.models.RealmModel;

/**
 * Interface for evaluating AAuth policies.
 * 
 * This interface provides extension points for policy evaluation in the AAuth protocol.
 * The default implementation uses realm attributes for simple allow/block list policies.
 * Future implementations can integrate with Keycloak's Authorization Services for
 * more sophisticated policy evaluation.
 */
public interface AAuthPolicyEvaluator {

    /**
     * Check if the AAuth protocol is enabled for the given realm.
     *
     * @param realm the realm to check
     * @return true if AAuth is enabled
     */
    boolean isProtocolEnabled(RealmModel realm);

    /**
     * Check if an agent is allowed to make requests.
     *
     * @param agentId the agent identifier (URL)
     * @param realm the realm
     * @return true if the agent is allowed
     */
    boolean isAgentAllowed(String agentId, RealmModel realm);

    /**
     * Check if a scope is allowed for agents to request.
     *
     * @param scope the scope to check
     * @param realm the realm
     * @return true if the scope is allowed
     */
    boolean isScopeAllowed(String scope, RealmModel realm);

    /**
     * Check if all scopes in a space-separated string are allowed.
     *
     * @param scopeString space-separated scopes
     * @param realm the realm
     * @return true if all scopes are allowed
     */
    boolean areScopesAllowed(String scopeString, RealmModel realm);

    /**
     * Check if a specific agent is allowed to request specific scopes.
     * This allows for agent-specific scope restrictions.
     *
     * @param agentId the agent identifier
     * @param scopeString space-separated scopes
     * @param realm the realm
     * @return true if the agent can request these scopes
     */
    boolean isAgentScopeAllowed(String agentId, String scopeString, RealmModel realm);

    /**
     * Check if token exchange is allowed.
     *
     * @param realm the realm
     * @return true if token exchange is enabled
     */
    boolean isExchangeEnabled(RealmModel realm);

    /**
     * Check if an upstream issuer is trusted for token exchange.
     *
     * @param upstreamIssuer the issuer URL from the upstream token
     * @param currentRealmIssuer the current realm's issuer URL
     * @param realm the realm
     * @return true if the upstream issuer is trusted
     */
    boolean isIssuerTrusted(String upstreamIssuer, String currentRealmIssuer, RealmModel realm);

    /**
     * Check if a token exchange is allowed given all parameters.
     *
     * @param upstreamIssuer the upstream token's issuer
     * @param agentId the agent performing the exchange
     * @param requestedScopes the scopes being requested
     * @param currentRealmIssuer the current realm's issuer
     * @param realm the realm
     * @return true if the exchange is allowed
     */
    boolean isExchangeAllowed(String upstreamIssuer, String agentId, String requestedScopes, 
                              String currentRealmIssuer, RealmModel realm);

    /**
     * Get the maximum allowed delegation chain depth.
     *
     * @param realm the realm
     * @return the maximum depth
     */
    int getMaxDelegationDepth(RealmModel realm);

    /**
     * Get the auth token lifespan in seconds.
     *
     * @param realm the realm
     * @return token lifespan in seconds
     */
    int getTokenLifespan(RealmModel realm);

    /**
     * Get the refresh token lifespan in seconds.
     *
     * @param realm the realm
     * @return refresh token lifespan in seconds
     */
    int getRefreshTokenLifespan(RealmModel realm);

    /**
     * Create a policy evaluation result with details.
     *
     * @param allowed whether the action is allowed
     * @param reason the reason for the decision
     * @return the evaluation result
     */
    default PolicyResult result(boolean allowed, String reason) {
        return new PolicyResult(allowed, reason);
    }

    /**
     * Result of a policy evaluation with details.
     */
    class PolicyResult {
        private final boolean allowed;
        private final String reason;

        public PolicyResult(boolean allowed, String reason) {
            this.allowed = allowed;
            this.reason = reason;
        }

        public boolean isAllowed() {
            return allowed;
        }

        public String getReason() {
            return reason;
        }

        public static PolicyResult allow() {
            return new PolicyResult(true, null);
        }

        public static PolicyResult allow(String reason) {
            return new PolicyResult(true, reason);
        }

        public static PolicyResult deny(String reason) {
            return new PolicyResult(false, reason);
        }
    }
}

