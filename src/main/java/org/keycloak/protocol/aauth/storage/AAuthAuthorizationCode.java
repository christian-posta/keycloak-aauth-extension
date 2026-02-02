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
 * Authorization code data for AAuth protocol.
 * 
 * Extends OAuth2Code with AAuth-specific fields like request token ID.
 */
public class AAuthAuthorizationCode {

    private static final String ID_NOTE = "id";
    private static final String EXPIRATION_NOTE = "exp";
    private static final String SCOPE_NOTE = "scope";
    private static final String REDIRECT_URI_PARAM_NOTE = "redirectUri";
    private static final String USER_SESSION_ID_NOTE = "user_session_id";
    private static final String REQUEST_TOKEN_ID_NOTE = "request_token_id";
    private static final String AGENT_ID_NOTE = "agent_id";
    private static final String AGENT_JKT_NOTE = "agent_jkt";
    private static final String SIGNATURE_SCHEME_NOTE = "signature_scheme";
    private static final String RESOURCE_ID_NOTE = "resource_id";

    private final String id;
    private final int expiration;
    private final String scope;
    private final String redirectUriParam;
    private final String userSessionId;
    private final String requestTokenId;
    private final String agentId;
    private final String agentJkt;
    private final String signatureScheme;
    private final String resourceId;

    public AAuthAuthorizationCode(String id, int expiration, String scope, String redirectUriParam,
            String userSessionId, String requestTokenId, String agentId, String agentJkt,
            String signatureScheme, String resourceId) {
        this.id = id;
        this.expiration = expiration;
        this.scope = scope;
        this.redirectUriParam = redirectUriParam;
        this.userSessionId = userSessionId;
        this.requestTokenId = requestTokenId;
        this.agentId = agentId;
        this.agentJkt = agentJkt;
        this.signatureScheme = signatureScheme;
        this.resourceId = resourceId;
    }

    private AAuthAuthorizationCode(Map<String, String> data) {
        id = data.get(ID_NOTE);
        expiration = Integer.parseInt(data.get(EXPIRATION_NOTE));
        scope = data.get(SCOPE_NOTE);
        redirectUriParam = data.get(REDIRECT_URI_PARAM_NOTE);
        userSessionId = data.get(USER_SESSION_ID_NOTE);
        requestTokenId = data.get(REQUEST_TOKEN_ID_NOTE);
        agentId = data.get(AGENT_ID_NOTE);
        agentJkt = data.get(AGENT_JKT_NOTE);
        signatureScheme = data.get(SIGNATURE_SCHEME_NOTE);
        resourceId = data.get(RESOURCE_ID_NOTE);
    }

    public static AAuthAuthorizationCode deserialize(Map<String, String> data) {
        return new AAuthAuthorizationCode(data);
    }

    public Map<String, String> serialize() {
        Map<String, String> result = new HashMap<>();
        result.put(ID_NOTE, id);
        result.put(EXPIRATION_NOTE, String.valueOf(expiration));
        if (scope != null) {
            result.put(SCOPE_NOTE, scope);
        }
        result.put(REDIRECT_URI_PARAM_NOTE, redirectUriParam);
        result.put(USER_SESSION_ID_NOTE, userSessionId);
        result.put(REQUEST_TOKEN_ID_NOTE, requestTokenId);
        result.put(AGENT_ID_NOTE, agentId);
        result.put(AGENT_JKT_NOTE, agentJkt);
        result.put(SIGNATURE_SCHEME_NOTE, signatureScheme);
        result.put(RESOURCE_ID_NOTE, resourceId);
        return result;
    }

    public String getId() {
        return id;
    }

    public int getExpiration() {
        return expiration;
    }

    public String getScope() {
        return scope;
    }

    public String getRedirectUriParam() {
        return redirectUriParam;
    }

    public String getUserSessionId() {
        return userSessionId;
    }

    public String getRequestTokenId() {
        return requestTokenId;
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
}

