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

package org.keycloak.protocol.aauth.storage;

import org.jboss.logging.Logger;
import org.keycloak.common.util.Base64Url;
import org.keycloak.common.util.Time;
import org.keycloak.models.KeycloakSession;
import org.keycloak.models.SingleUseObjectProvider;

import java.util.Map;
import java.util.UUID;

/**
 * Store and retrieve AAuth request tokens.
 * 
 * Uses Keycloak's SingleUseObjectProvider for single-use token storage,
 * similar to how OAuth2Code is stored.
 */
public class AAuthRequestTokenStore {

    private static final Logger logger = Logger.getLogger(AAuthRequestTokenStore.class);
    private static final int DEFAULT_LIFESPAN = 600; // 10 minutes

    private final KeycloakSession session;

    public AAuthRequestTokenStore(KeycloakSession session) {
        this.session = session;
    }

    /**
     * Create and store a request token.
     * 
     * @param agentId Agent identifier
     * @param agentJkt Agent JWK thumbprint
     * @param signatureScheme Signature scheme used
     * @param resourceId Resource identifier
     * @param scope Requested scope (or null)
     * @param authRequestUrl Auth request URL (or null)
     * @param redirectUri Redirect URI for callback
     * @param state Optional state parameter
     * @return Opaque request token string
     */
    public String createRequestToken(String agentId, String agentJkt, String signatureScheme,
            String resourceId, String scope, String authRequestUrl, String redirectUri, String state) {
        
        String id = UUID.randomUUID().toString();
        int expiration = Time.currentTime() + DEFAULT_LIFESPAN;
        
        AAuthRequestToken requestToken = new AAuthRequestToken(
                id, expiration, agentId, agentJkt, signatureScheme, resourceId,
                scope, authRequestUrl, redirectUri, state);
        
        SingleUseObjectProvider store = session.singleUseObjects();
        Map<String, String> serialized = requestToken.serialize();
        store.put(id, DEFAULT_LIFESPAN, serialized);
        
        // Create opaque token: {id}.{timestamp}.{hash}
        long timestamp = Time.currentTime();
        String hash = Base64Url.encode((id + ":" + timestamp + ":" + agentId).getBytes(java.nio.charset.StandardCharsets.UTF_8));
        String opaqueToken = id + "." + timestamp + "." + hash;
        
        logger.debugf("Created request token for agent: %s, resource: %s", agentId, resourceId);
        
        return opaqueToken;
    }

    /**
     * Validate and retrieve request token data.
     * 
     * @param requestToken Opaque request token string
     * @return Request token data or null if invalid/expired
     */
    public AAuthRequestToken validateRequestToken(String requestToken) {
        if (requestToken == null || requestToken.isEmpty()) {
            return null;
        }
        
        String[] parts = requestToken.split("\\.", 3);
        if (parts.length != 3) {
            logger.warn("Invalid request token format");
            return null;
        }
        
        String id = parts[0];
        SingleUseObjectProvider store = session.singleUseObjects();
        Map<String, String> data = store.get(id);
        
        if (data == null) {
            logger.debugf("Request token not found or already used: %s", id);
            return null;
        }
        
        AAuthRequestToken token = AAuthRequestToken.deserialize(data);
        
        // Check expiration
        if (Time.currentTime() > token.getExpiration()) {
            logger.debugf("Request token expired: %s", id);
            store.remove(id); // Clean up expired token
            return null;
        }
        
        return token;
    }

    /**
     * Consume (remove) a request token after use.
     * 
     * @param requestToken Opaque request token string
     * @return True if token was found and removed, false otherwise
     */
    public boolean consumeRequestToken(String requestToken) {
        if (requestToken == null || requestToken.isEmpty()) {
            return false;
        }
        
        String[] parts = requestToken.split("\\.", 3);
        if (parts.length != 3) {
            return false;
        }
        
        String id = parts[0];
        SingleUseObjectProvider store = session.singleUseObjects();
        Map<String, String> data = store.remove(id);
        
        if (data != null) {
            logger.debugf("Consumed request token: %s", id);
            return true;
        }
        
        return false;
    }

    /**
     * Retrieve request token by ID directly (for consent flow).
     * 
     * @param id Request token ID
     * @return Request token data or null if invalid/expired
     */
    public AAuthRequestToken getRequestTokenById(String id) {
        if (id == null || id.isEmpty()) {
            return null;
        }
        
        SingleUseObjectProvider store = session.singleUseObjects();
        Map<String, String> data = store.get(id);
        
        if (data == null) {
            logger.debugf("Request token not found: %s", id);
            return null;
        }
        
        AAuthRequestToken token = AAuthRequestToken.deserialize(data);
        
        // Check expiration
        if (Time.currentTime() > token.getExpiration()) {
            logger.debugf("Request token expired: %s", id);
            store.remove(id); // Clean up expired token
            return null;
        }
        
        return token;
    }
}

