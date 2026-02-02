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

package org.keycloak.protocol.aauth.wellknown;

import org.keycloak.Config;
import org.keycloak.models.KeycloakSession;
import org.keycloak.models.KeycloakSessionFactory;
import org.keycloak.wellknown.WellKnownProvider;
import org.keycloak.wellknown.WellKnownProviderFactory;

/**
 * Factory for AAuth Issuer Well-Known Provider.
 */
public class AAuthIssuerWellKnownProviderFactory implements WellKnownProviderFactory {

    public static final String PROVIDER_ID = "aauth-issuer";

    @Override
    public WellKnownProvider create(KeycloakSession session) {
        return new AAuthIssuerWellKnownProvider(session);
    }

    @Override
    public void init(Config.Scope config) {
        // No configuration needed for Phase 2
    }

    @Override
    public void postInit(KeycloakSessionFactory factory) {
        // No post-init needed
    }

    @Override
    public void close() {
        // No cleanup needed
    }

    @Override
    public String getId() {
        return PROVIDER_ID;
    }

    @Override
    public String getAlias() {
        return PROVIDER_ID;
    }

    @Override
    public int getPriority() {
        return 100; // Default priority
    }
}

