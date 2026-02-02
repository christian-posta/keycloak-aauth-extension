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

package org.keycloak.protocol.aauth.util;

import com.fasterxml.jackson.databind.JsonNode;
import org.jboss.logging.Logger;
import org.keycloak.common.util.Base64Url;
import org.keycloak.crypto.KeyType;
import org.keycloak.jose.jwk.ECPublicJWK;
import org.keycloak.jose.jwk.JWK;
import org.keycloak.jose.jwk.OKPPublicJWK;
import org.keycloak.jose.jwk.RSAPublicJWK;
import org.keycloak.jose.jws.crypto.HashUtils;
import org.keycloak.util.JsonSerialization;

import java.io.IOException;
import java.util.HashMap;
import java.util.Map;
import java.util.TreeMap;

/**
 * Utility class for JWK operations in AAuth extension.
 * 
 * Provides JWK thumbprint computation functionality that is needed by AAuthTokenManager.
 * This is a copy of the computeThumbprint method from Keycloak's JWKSUtils class.
 */
public class AAuthJWKSUtils {

    private static final Logger logger = Logger.getLogger(AAuthJWKSUtils.class);

    private static final String JWK_THUMBPRINT_DEFAULT_HASH_ALGORITHM = "SHA-256";
    private static final Map<String, String[]> JWK_THUMBPRINT_REQUIRED_MEMBERS = new HashMap<>();

    static {
        JWK_THUMBPRINT_REQUIRED_MEMBERS.put(KeyType.RSA, new String[] { RSAPublicJWK.MODULUS, RSAPublicJWK.PUBLIC_EXPONENT });
        JWK_THUMBPRINT_REQUIRED_MEMBERS.put(KeyType.EC, new String[] { ECPublicJWK.CRV, ECPublicJWK.X, ECPublicJWK.Y });
        JWK_THUMBPRINT_REQUIRED_MEMBERS.put(KeyType.OKP, new String[] { OKPPublicJWK.CRV, OKPPublicJWK.X });
    }

    /**
     * Compute JWK thumbprint per RFC 7638.
     * 
     * @param key The JWK to compute thumbprint for
     * @return Base64Url-encoded thumbprint
     */
    public static String computeThumbprint(JWK key) {
        return computeThumbprint(key, JWK_THUMBPRINT_DEFAULT_HASH_ALGORITHM);
    }

    /**
     * Compute JWK thumbprint per RFC 7638 with specified hash algorithm.
     * 
     * TreeMap uses the natural ordering of the keys.
     * Therefore, it follows the way of hash value calculation for a public key defined by RFC 7638
     * 
     * @param key The JWK to compute thumbprint for
     * @param hashAlg The hash algorithm to use (e.g., "SHA-256")
     * @return Base64Url-encoded thumbprint
     */
    public static String computeThumbprint(JWK key, String hashAlg) {
        String kty = key.getKeyType();
        String[] requiredMembers = JWK_THUMBPRINT_REQUIRED_MEMBERS.get(kty);

        // e.g. `oct`, see RFC 7638 Section 3.2
        if (requiredMembers == null) {
            throw new UnsupportedOperationException("Unsupported key type: " + kty);
        }

        Map<String, String> members = new TreeMap<>();
        members.put(JWK.KEY_TYPE, kty);

        try {
            JsonNode node = JsonSerialization.writeValueAsNode(key);
            for (String member : requiredMembers) {
                members.put(member, node.get(member).asText());
            }

            byte[] bytes = JsonSerialization.writeValueAsBytes(members);
            byte[] hash = HashUtils.hash(hashAlg, bytes);
            return Base64Url.encode(hash);
        } catch (IOException ex) {
            logger.debugf(ex, "Failed to compute JWK thumbprint for key '%s'.", key.getKeyId());
            return null;
        }
    }
}
