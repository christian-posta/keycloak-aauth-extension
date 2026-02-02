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

import org.keycloak.jose.jwk.JWK;
import org.keycloak.jose.jwk.JWKParser;
import org.keycloak.protocol.aauth.signing.SignatureKeyParser;
import org.keycloak.protocol.aauth.signing.exceptions.SignatureVerificationException;
import org.keycloak.util.JsonSerialization;

import java.security.PublicKey;
import java.util.HashMap;
import java.util.Map;

/**
 * Signature scheme handler for scheme=hwk (Header Web Key).
 * 
 * Extracts the public key directly from the Signature-Key header parameters.
 * This is a pseudonymous scheme - no agent identity is verified.
 */
public class HeaderWebKeyScheme implements SignatureScheme {

    @Override
    public PublicKey discoverPublicKey(SignatureKeyParser keyParser) throws Exception {
        Map<String, String> jwkParams = keyParser.getJWKParameters();
        
        if (jwkParams.isEmpty()) {
            throw new SignatureVerificationException("Missing JWK parameters in Signature-Key header for scheme=hwk");
        }

        String kty = jwkParams.get("kty");
        if (kty == null) {
            throw new SignatureVerificationException("Missing 'kty' parameter in JWK");
        }
        
        // Build JWK JSON from parameters
        Map<String, Object> jwkJson = new HashMap<>();
        jwkJson.put("kty", kty);
        jwkJson.putAll(jwkParams);
        
        // Parse JWK from JSON
        String jwkJsonString = JsonSerialization.writeValueAsString(jwkJson);
        JWK jwk = JsonSerialization.readValue(jwkJsonString, JWK.class);
        
        // Convert to PublicKey using JWKParser
        return JWKParser.create(jwk).toPublicKey();
    }

    @Override
    public String getAlgorithm(SignatureKeyParser keyParser) {
        Map<String, String> jwkParams = keyParser.getJWKParameters();
        String kty = jwkParams.get("kty");
        String crv = jwkParams.get("crv");
        
        if ("OKP".equals(kty) && "Ed25519".equals(crv)) {
            return "Ed25519";
        }
        if ("RSA".equals(kty)) {
            // Default to RS256 for RSA, could be determined from other parameters
            return "RS256";
        }
        if ("EC".equals(kty)) {
            if ("P-256".equals(crv)) {
                return "ES256";
            }
            if ("P-384".equals(crv)) {
                return "ES384";
            }
            if ("P-521".equals(crv)) {
                return "ES512";
            }
        }
        
        // Default fallback
        return "RS256";
    }

    @Override
    public String getAgentId(SignatureKeyParser keyParser) {
        // Pseudonymous scheme - no agent identity
        return null;
    }
}

