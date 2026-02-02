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

import java.util.HashMap;
import java.util.Map;

/**
 * Data associated with an AAuth request token.
 * 
 * Similar to OAuth2Code but for AAuth request tokens. Stores pending authorization
 * requests that require user consent.
 * 
 * @author Red Hat
 */
public class AAuthRequestToken {

    private static final String ID_NOTE = "id";
    private static final String EXPIRATION_NOTE = "exp";
    private static final String AGENT_ID_NOTE = "agent_id";
    private static final String AGENT_JKT_NOTE = "agent_jkt";
    private static final String SIGNATURE_SCHEME_NOTE = "signature_scheme";
    private static final String RESOURCE_ID_NOTE = "resource_id";
    private static final String SCOPE_NOTE = "scope";
    private static final String AUTH_REQUEST_URL_NOTE = "auth_request_url";
    private static final String REDIRECT_URI_NOTE = "redirect_uri";
    private static final String STATE_NOTE = "state";

    private final String id;
    private final int expiration;
    private final String agentId;
    private final String agentJkt;
    private final String signatureScheme;
    private final String resourceId;
    private final String scope;
    private final String authRequestUrl;
    private final String redirectUri;
    private final String state;

    public AAuthRequestToken(String id, int expiration, String agentId, String agentJkt,
            String signatureScheme, String resourceId, String scope, String authRequestUrl,
            String redirectUri, String state) {
        this.id = id;
        this.expiration = expiration;
        this.agentId = agentId;
        this.agentJkt = agentJkt;
        this.signatureScheme = signatureScheme;
        this.resourceId = resourceId;
        this.scope = scope;
        this.authRequestUrl = authRequestUrl;
        this.redirectUri = redirectUri;
        this.state = state;
    }

    private AAuthRequestToken(Map<String, String> data) {
        id = data.get(ID_NOTE);
        expiration = Integer.parseInt(data.get(EXPIRATION_NOTE));
        agentId = data.get(AGENT_ID_NOTE);
        agentJkt = data.get(AGENT_JKT_NOTE);
        signatureScheme = data.get(SIGNATURE_SCHEME_NOTE);
        resourceId = data.get(RESOURCE_ID_NOTE);
        scope = data.get(SCOPE_NOTE);
        authRequestUrl = data.get(AUTH_REQUEST_URL_NOTE);
        redirectUri = data.get(REDIRECT_URI_NOTE);
        state = data.get(STATE_NOTE);
    }

    public static AAuthRequestToken deserialize(Map<String, String> data) {
        return new AAuthRequestToken(data);
    }

    public Map<String, String> serialize() {
        Map<String, String> result = new HashMap<>();
        result.put(ID_NOTE, id);
        result.put(EXPIRATION_NOTE, String.valueOf(expiration));
        result.put(AGENT_ID_NOTE, agentId);
        result.put(AGENT_JKT_NOTE, agentJkt);
        result.put(SIGNATURE_SCHEME_NOTE, signatureScheme);
        result.put(RESOURCE_ID_NOTE, resourceId);
        if (scope != null) {
            result.put(SCOPE_NOTE, scope);
        }
        if (authRequestUrl != null) {
            result.put(AUTH_REQUEST_URL_NOTE, authRequestUrl);
        }
        result.put(REDIRECT_URI_NOTE, redirectUri);
        if (state != null) {
            result.put(STATE_NOTE, state);
        }
        return result;
    }

    public String getId() {
        return id;
    }

    public int getExpiration() {
        return expiration;
    }

    public String getAgentId() {
        return agentId;
    }

    public String getAgentJkt() {
        return agentJkt;
    }

    public String getSignatureScheme() {
        return signatureScheme;
    }

    public String getResourceId() {
        return resourceId;
    }

    public String getScope() {
        return scope;
    }

    public String getAuthRequestUrl() {
        return authRequestUrl;
    }

    public String getRedirectUri() {
        return redirectUri;
    }

    public String getState() {
        return state;
    }
}

