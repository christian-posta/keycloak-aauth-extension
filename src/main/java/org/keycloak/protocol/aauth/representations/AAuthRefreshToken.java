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
import org.keycloak.TokenCategory;
import org.keycloak.jose.jwk.JWK;
import org.keycloak.representations.AccessToken;

/**
 * AAuth Refresh Token representation.
 * 
 * Extends AccessToken to add AAuth-specific claims for agent identity binding:
 * - agent: Agent identifier (HTTPS URL or pseudonymous)
 * - agent_jkt: Agent JWK thumbprint
 * - agent_delegate: Optional agent delegate identifier
 * - resource_id: Resource identifier (aud claim)
 * - cnf.jwk: Agent's public signing key (proof-of-possession)
 * 
 * Token type: "refresh+jwt"
 */
public class AAuthRefreshToken extends AccessToken {

    @JsonProperty("agent")
    private String agent;

    @JsonProperty("agent_jkt")
    private String agentJkt;

    @JsonProperty("agent_delegate")
    private String agentDelegate;

    @JsonProperty("resource_id")
    private String resourceId;

    @JsonProperty("cnf")
    private CnfClaim cnf;

    public AAuthRefreshToken() {
        super();
        // Set type to refresh+jwt for AAuth
        type("refresh+jwt");
    }

    /**
     * Create AAuth refresh token from AAuth token.
     */
    public AAuthRefreshToken(AAuthToken token) {
        super();
        type("refresh+jwt");
        // Copy base fields from AAuthToken
        this.issuer = token.getIssuer();
        this.subject = token.getSubject();
        this.audience = token.getAudience();
        this.scope = token.getScope();
        // Session ID and nonce are not in JsonWebToken, so get from other claims if present
        if (token.getOtherClaims() != null) {
            Object sessionId = token.getOtherClaims().get("sid");
            if (sessionId != null) {
                this.sessionId = sessionId.toString();
            }
            Object nonce = token.getOtherClaims().get("nonce");
            if (nonce != null) {
                this.nonce = nonce.toString();
            }
        }
        
        // Copy AAuth-specific fields
        this.agent = token.getAgent();
        this.agentDelegate = token.getAgentDelegate();
        this.resourceId = token.getAudience() != null && token.getAudience().length > 0 
            ? token.getAudience()[0] : null;
        if (token.getCnf() != null) {
            this.cnf = new CnfClaim();
            this.cnf.jwk = token.getCnf().getJwk();
        }
    }

    public String getAgent() {
        return agent;
    }

    public AAuthRefreshToken agent(String agent) {
        this.agent = agent;
        return this;
    }

    public String getAgentJkt() {
        return agentJkt;
    }

    public AAuthRefreshToken agentJkt(String agentJkt) {
        this.agentJkt = agentJkt;
        return this;
    }

    public String getAgentDelegate() {
        return agentDelegate;
    }

    public AAuthRefreshToken agentDelegate(String agentDelegate) {
        this.agentDelegate = agentDelegate;
        return this;
    }

    public String getResourceId() {
        return resourceId;
    }

    public AAuthRefreshToken resourceId(String resourceId) {
        this.resourceId = resourceId;
        return this;
    }

    public CnfClaim getCnf() {
        return cnf;
    }

    public AAuthRefreshToken setCnf(CnfClaim cnf) {
        this.cnf = cnf;
        return this;
    }

    public AAuthRefreshToken setCnfJwk(JWK jwk) {
        if (this.cnf == null) {
            this.cnf = new CnfClaim();
        }
        this.cnf.jwk = jwk;
        return this;
    }

    @Override
    public TokenCategory getCategory() {
        return TokenCategory.INTERNAL;
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
