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

package org.keycloak.protocol.aauth.grants;

import org.keycloak.Config;
import org.keycloak.models.KeycloakSession;
import org.keycloak.models.KeycloakSessionFactory;
import org.keycloak.protocol.oidc.grants.OAuth2GrantType;
import org.keycloak.protocol.oidc.grants.OAuth2GrantTypeFactory;

/**
 * Factory for AAuth Refresh Token Grant Type.
 */
public class RefreshGrantTypeFactory implements OAuth2GrantTypeFactory {

    public static final String GRANT_TYPE = "refresh";

    @Override
    public String getId() {
        return GRANT_TYPE;
    }

    @Override
    public String getShortcut() {
        return GRANT_TYPE;
    }

    @Override
    public OAuth2GrantType create(KeycloakSession session) {
        return new RefreshGrantType();
    }

    @Override
    public void init(Config.Scope config) {
        // No configuration needed
    }

    @Override
    public void postInit(KeycloakSessionFactory factory) {
        // No post-init needed
    }

    @Override
    public void close() {
        // No cleanup needed
    }
}

