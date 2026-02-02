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
import com.fasterxml.jackson.annotation.JsonInclude;

import java.util.Map;

/**
 * Actor claim representation for AAuth token exchange.
 * 
 * Represents the `act` claim that shows the delegation chain in token exchange scenarios.
 * Based on RFC 8693 Section 4.2 and AAuth specification Section 7.5.
 * 
 * The `act` claim contains information about the upstream agent that delegated access.
 * It supports nested structures for multi-hop delegation chains.
 */
@JsonInclude(JsonInclude.Include.NON_NULL)
public class AAuthActorClaim {

    /**
     * REQUIRED: The HTTPS URL of the upstream agent (from the upstream token's `agent` claim).
     */
    @JsonProperty("agent")
    private String agent;

    /**
     * OPTIONAL: The upstream agent delegate identifier (from the upstream token's `agent_delegate` claim).
     */
    @JsonProperty("agent_delegate")
    private String agentDelegate;

    /**
     * OPTIONAL: The user subject from the upstream token (from the upstream token's `sub` claim).
     */
    @JsonProperty("sub")
    private String sub;

    /**
     * OPTIONAL: Nested actor claim for multi-hop delegation chains.
     * Contains the upstream actor claim from the upstream token.
     */
    @JsonProperty("act")
    private AAuthActorClaim act;

    /**
     * OPTIONAL: Additional claims from the upstream token.
     * Can include scope, issuer, or other relevant claims.
     */
    @JsonProperty("claims")
    private Map<String, Object> claims;

    public AAuthActorClaim() {
    }

    public AAuthActorClaim(String agent) {
        this.agent = agent;
    }

    public String getAgent() {
        return agent;
    }

    public AAuthActorClaim setAgent(String agent) {
        this.agent = agent;
        return this;
    }

    public String getAgentDelegate() {
        return agentDelegate;
    }

    public AAuthActorClaim setAgentDelegate(String agentDelegate) {
        this.agentDelegate = agentDelegate;
        return this;
    }

    public String getSub() {
        return sub;
    }

    public AAuthActorClaim setSub(String sub) {
        this.sub = sub;
        return this;
    }

    public AAuthActorClaim getAct() {
        return act;
    }

    public AAuthActorClaim setAct(AAuthActorClaim act) {
        this.act = act;
        return this;
    }

    public Map<String, Object> getClaims() {
        return claims;
    }

    public AAuthActorClaim setClaims(Map<String, Object> claims) {
        this.claims = claims;
        return this;
    }

    /**
     * Convert to Map for inclusion in JWT claims.
     */
    public Map<String, Object> toMap() {
        Map<String, Object> map = new java.util.HashMap<>();
        if (agent != null) {
            map.put("agent", agent);
        }
        if (agentDelegate != null) {
            map.put("agent_delegate", agentDelegate);
        }
        if (sub != null) {
            map.put("sub", sub);
        }
        if (act != null) {
            map.put("act", act.toMap());
        }
        if (claims != null) {
            map.putAll(claims);
        }
        return map;
    }

    /**
     * Build actor claim from upstream auth token.
     * 
     * @param upstreamToken The upstream auth token
     * @return Actor claim representing the upstream agent
     */
    public static AAuthActorClaim fromUpstreamToken(org.keycloak.protocol.aauth.representations.AAuthToken upstreamToken) {
        AAuthActorClaim actor = new AAuthActorClaim();
        
        // Extract agent from upstream token
        String upstreamAgent = upstreamToken.getAgent();
        if (upstreamAgent == null && upstreamToken.getAudience() != null && upstreamToken.getAudience().length > 0) {
            // If no agent claim, use aud as agent (agent-as-resource scenario)
            upstreamAgent = upstreamToken.getAudience()[0];
        }
        actor.setAgent(upstreamAgent);
        
        // Extract agent_delegate if present
        actor.setAgentDelegate(upstreamToken.getAgentDelegate());
        
        // Extract user subject if present
        actor.setSub(upstreamToken.getSubject());
        
        // Extract nested act claim if present (multi-hop)
        Map<String, Object> upstreamAct = upstreamToken.getAct();
        if (upstreamAct != null) {
            // Convert map to AAuthActorClaim
            actor.setAct(fromMap(upstreamAct));
        }
        
        // Store additional claims if needed
        Map<String, Object> additionalClaims = new java.util.HashMap<>();
        if (upstreamToken.getScope() != null) {
            additionalClaims.put("scope", upstreamToken.getScope());
        }
        if (upstreamToken.getIssuer() != null) {
            additionalClaims.put("iss", upstreamToken.getIssuer());
        }
        if (!additionalClaims.isEmpty()) {
            actor.setClaims(additionalClaims);
        }
        
        return actor;
    }

    /**
     * Convert Map to AAuthActorClaim (for nested act claims).
     */
    @SuppressWarnings("unchecked")
    public static AAuthActorClaim fromMap(Map<String, Object> map) {
        AAuthActorClaim actor = new AAuthActorClaim();
        
        if (map.containsKey("agent")) {
            actor.setAgent((String) map.get("agent"));
        }
        if (map.containsKey("agent_delegate")) {
            actor.setAgentDelegate((String) map.get("agent_delegate"));
        }
        if (map.containsKey("sub")) {
            actor.setSub((String) map.get("sub"));
        }
        if (map.containsKey("act")) {
            Object nestedAct = map.get("act");
            if (nestedAct instanceof Map) {
                actor.setAct(fromMap((Map<String, Object>) nestedAct));
            }
        }
        if (map.containsKey("claims")) {
            actor.setClaims((Map<String, Object>) map.get("claims"));
        }
        
        return actor;
    }
}
