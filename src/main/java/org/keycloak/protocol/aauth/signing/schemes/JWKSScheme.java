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

package org.keycloak.protocol.aauth.signing.schemes;

import org.jboss.logging.Logger;
import org.keycloak.jose.jwk.JWK;
import org.keycloak.jose.jwk.JWKParser;
import org.keycloak.jose.jwk.JSONWebKeySet;
import org.keycloak.models.KeycloakSession;
import org.keycloak.protocol.aauth.metadata.AgentMetadata;
import org.keycloak.protocol.aauth.metadata.MetadataFetcher;
import org.keycloak.protocol.aauth.signing.SignatureKeyParser;
import org.keycloak.protocol.aauth.signing.exceptions.SignatureVerificationException;

import java.security.PublicKey;

/**
 * Signature scheme handler for scheme=jwks (JWKS Discovery - Identified Signer).
 * 
 * Supports two mutually exclusive modes:
 * - Mode 1: Direct JWKS URL (uses 'jwks' parameter)
 * - Mode 2: Identifier + Metadata (uses 'id' parameter, fetches metadata to get jwks_uri)
 * 
 * See AAuth spec Section 10.7 for details.
 */
public class JWKSScheme implements SignatureScheme {

    private static final Logger logger = Logger.getLogger(JWKSScheme.class);

    private final KeycloakSession session;

    public JWKSScheme(KeycloakSession session) {
        this.session = session;
    }

    @Override
    public PublicKey discoverPublicKey(SignatureKeyParser keyParser) throws Exception {
        String kid = keyParser.getKid();
        if (kid == null) {
            throw new SignatureVerificationException("Missing 'kid' parameter in Signature-Key for scheme=jwks");
        }

        String jwksUrl = keyParser.getParameter("jwks");
        String agentId = keyParser.getAgentId();
        String wellKnown = keyParser.getWellKnown();

        // Determine mode: Mode 1 (direct JWKS URL) vs Mode 2 (identifier + metadata)
        if (jwksUrl != null && agentId != null) {
            throw new SignatureVerificationException("Both 'jwks' and 'id' parameters present for scheme=jwks. These are mutually exclusive.");
        }
        if (jwksUrl == null && agentId == null) {
            throw new SignatureVerificationException("Either 'jwks' (Mode 1) or 'id' (Mode 2) parameter required for scheme=jwks");
        }

        String jwksUri;
        String cacheKey;

        if (jwksUrl != null) {
            // Mode 1: Direct JWKS URL
            if (wellKnown != null) {
                throw new SignatureVerificationException("'well-known' parameter must not be present when using Mode 1 (direct JWKS URL) for scheme=jwks");
            }
            jwksUri = jwksUrl;
            cacheKey = "aauth.jwks.mode1." + jwksUrl + "." + kid;
        } else {
            // Mode 2: Identifier + Metadata
            if (wellKnown == null) {
                wellKnown = "aauth-agent"; // Default
            }

            // Fetch agent metadata
            MetadataFetcher fetcher = new MetadataFetcher(session);
            AgentMetadata metadata = fetcher.fetchAgentMetadata(agentId, wellKnown);
            
            if (metadata == null || metadata.getJwksUri() == null) {
                throw new SignatureVerificationException("Failed to fetch agent metadata or jwks_uri not found");
            }

            jwksUri = metadata.getJwksUri();
            cacheKey = "aauth.jwks.mode2." + agentId + "." + kid;
        }

        // Fetch JWKS
        MetadataFetcher fetcher = new MetadataFetcher(session);
        JSONWebKeySet jwks = fetcher.fetchJWKS(jwksUri);
        
        if (jwks == null || jwks.getKeys() == null) {
            throw new SignatureVerificationException("Failed to fetch JWKS or no keys found");
        }

        // Find key by kid and cache it for algorithm extraction
        JWK foundKey = null;
        for (JWK jwk : jwks.getKeys()) {
            if (kid.equals(jwk.getKeyId())) {
                foundKey = jwk;
                break;
            }
        }

        if (foundKey == null) {
            throw new SignatureVerificationException("Key with kid='" + kid + "' not found in JWKS");
        }

        // Store the found key in session for algorithm extraction
        session.setAttribute(cacheKey, foundKey);

        return JWKParser.create(foundKey).toPublicKey();
    }

    @Override
    public String getAlgorithm(SignatureKeyParser keyParser) {
        // Retrieve cached JWK to determine algorithm
        String kid = keyParser.getKid();
        String jwksUrl = keyParser.getParameter("jwks");
        String agentId = keyParser.getAgentId();
        
        String cacheKey;
        if (jwksUrl != null) {
            cacheKey = "aauth.jwks.mode1." + jwksUrl + "." + kid;
        } else if (agentId != null) {
            cacheKey = "aauth.jwks.mode2." + agentId + "." + kid;
        } else {
            return "Ed25519"; // Default fallback
        }
        
        JWK cachedKey = (JWK) session.getAttribute(cacheKey);
        if (cachedKey != null && cachedKey.getAlgorithm() != null) {
            return cachedKey.getAlgorithm();
        }
        
        // Default fallback
        return "Ed25519";
    }

    @Override
    public String getAgentId(SignatureKeyParser keyParser) {
        // For Mode 2, agent ID is the 'id' parameter
        // For Mode 1, there's no agent identity (just a JWKS URL)
        String agentId = keyParser.getAgentId();
        logger.debugf("JWKSScheme.getAgentId: id parameter = %s, all params = %s", 
                agentId, keyParser.getParameters());
        return agentId;
    }
}

