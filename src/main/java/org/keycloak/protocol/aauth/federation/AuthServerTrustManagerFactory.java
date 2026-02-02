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

package org.keycloak.protocol.aauth.federation;

import org.keycloak.Config;
import org.keycloak.models.KeycloakSession;
import org.keycloak.models.KeycloakSessionFactory;
import org.keycloak.models.RealmModel;

/**
 * Factory for AuthServerTrustManager.
 * 
 * Provides a simple way to create trust managers for realms.
 */
public class AuthServerTrustManagerFactory {

    /**
     * Create a trust manager for the given realm.
     * 
     * @param session The Keycloak session
     * @param realm The realm
     * @return Trust manager instance
     */
    public static AuthServerTrustManager create(KeycloakSession session, RealmModel realm) {
        return new AuthServerTrustManager(session, realm);
    }
}

