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
import org.keycloak.jose.jwk.JWK;
import org.keycloak.representations.JsonWebToken;

import java.util.Map;

/**
 * AAuth Token representation as defined in AAuth specification Section 7.
 * 
 * Extends JsonWebToken to add AAuth-specific claims:
 * - agent: Agent HTTPS URL
 * - agent_delegate: Agent delegate identifier (optional)
 * - cnf.jwk: Agent's public signing key (proof-of-possession)
 * - scope: Space-separated scopes (optional)
 * - act: Actor claim for token exchange (optional, Phase 4)
 */
public class AAuthToken extends JsonWebToken {

    @JsonProperty("agent")
    private String agent;

    @JsonProperty("agent_delegate")
    private String agentDelegate;

    @JsonProperty("cnf")
    private CnfClaim cnf;

    @JsonProperty("scope")
    private String scope;

    @JsonProperty("act")
    private Map<String, Object> act;

    public String getAgent() {
        return agent;
    }

    public AAuthToken agent(String agent) {
        this.agent = agent;
        return this;
    }

    public String getAgentDelegate() {
        return agentDelegate;
    }

    public AAuthToken agentDelegate(String agentDelegate) {
        this.agentDelegate = agentDelegate;
        return this;
    }

    public CnfClaim getCnf() {
        return cnf;
    }

    public AAuthToken setCnf(CnfClaim cnf) {
        this.cnf = cnf;
        return this;
    }

    public AAuthToken setCnfJwk(JWK jwk) {
        if (this.cnf == null) {
            this.cnf = new CnfClaim();
        }
        this.cnf.jwk = jwk;
        return this;
    }

    public String getScope() {
        return scope;
    }

    public AAuthToken setScope(String scope) {
        this.scope = scope;
        return this;
    }

    public Map<String, Object> getAct() {
        return act;
    }

    public AAuthToken setAct(Map<String, Object> act) {
        this.act = act;
        return this;
    }

    /**
     * Confirmation claim containing the agent's public key.
     */
    public static class CnfClaim {
        @JsonProperty("jwk")
        private JWK jwk;

        public JWK getJwk() {
            return jwk;
        }

        public void setJwk(JWK jwk) {
            this.jwk = jwk;
        }
    }
}
