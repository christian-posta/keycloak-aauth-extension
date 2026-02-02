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

package org.keycloak.protocol.aauth;

import org.jboss.logging.Logger;
import org.keycloak.Config;
import org.keycloak.events.EventBuilder;
import org.keycloak.models.ClientModel;
import org.keycloak.models.KeycloakSession;
import org.keycloak.models.KeycloakSessionFactory;
import org.keycloak.models.ProtocolMapperModel;
import org.keycloak.models.RealmModel;
import org.keycloak.protocol.LoginProtocol;
import org.keycloak.protocol.LoginProtocolFactory;
import org.keycloak.representations.idm.ClientRepresentation;

import java.util.Collections;
import java.util.Map;

/**
 * Factory for AAuth protocol endpoints.
 */
public class AAuthLoginProtocolFactory implements LoginProtocolFactory {

    private static final Logger logger = Logger.getLogger(AAuthLoginProtocolFactory.class);

    public static final String PROTOCOL_ID = "aauth";

    @Override
    public void init(Config.Scope config) {
        // No configuration needed for Phase 2
    }

    @Override
    public void postInit(KeycloakSessionFactory factory) {
        // Register JAX-RS filter for HTTP signature verification
        registerJaxRsFilter();
    }

    /**
     * Register the AAuthSignatureFilter as a JAX-RS provider.
     * 
     * This attempts to register the filter programmatically as a fallback
     * if @Provider annotation auto-discovery doesn't work.
     */
    private void registerJaxRsFilter() {
        try {
            // Try RESTEasy Classic (if available)
            Class<?> resteasyClass = Class.forName("org.jboss.resteasy.spi.ResteasyProviderFactory");
            Object providerFactory = resteasyClass.getMethod("getInstance").invoke(null);
            providerFactory.getClass().getMethod("registerProvider", Class.class)
                .invoke(providerFactory, org.keycloak.protocol.aauth.filters.AAuthSignatureFilter.class);
            logger.info("AAuthSignatureFilter registered via RESTEasy Classic");
            return;
        } catch (ClassNotFoundException e) {
            // RESTEasy Classic not available, try RESTEasy Reactive
            logger.debug("RESTEasy Classic not found, filter should be auto-discovered via @Provider annotation");
        } catch (Exception e) {
            logger.warn("Could not register AAuthSignatureFilter programmatically. " +
                       "Relying on @Provider annotation auto-discovery.", e);
        }
        
        // For RESTEasy Reactive (Quarkus default), @Provider annotation should be sufficient
        // If auto-discovery doesn't work, the filter will still be registered via beans.xml
        logger.debug("AAuthSignatureFilter should be auto-discovered via @Provider annotation");
    }

    @Override
    public void close() {
        // No cleanup needed
    }

    @Override
    public Map<String, ProtocolMapperModel> getBuiltinMappers() {
        // No built-in mappers for Phase 2
        return Collections.emptyMap();
    }

    @Override
    public Object createProtocolEndpoint(KeycloakSession session, EventBuilder event) {
        return new AAuthProtocolService(session, event);
    }

    @Override
    public void createDefaultClientScopes(RealmModel newRealm, boolean addScopesToExistingClients) {
        // No default client scopes for Phase 2
    }

    @Override
    public void setupClientDefaults(ClientRepresentation rep, ClientModel newClient) {
        // No client defaults for Phase 2
    }

    @Override
    public LoginProtocol create(KeycloakSession session) {
        return new AAuthLoginProtocol();
    }

    @Override
    public String getId() {
        return PROTOCOL_ID;
    }
}

