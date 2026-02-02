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

import org.keycloak.models.KeycloakSession;
import org.keycloak.models.RealmModel;
import org.keycloak.protocol.aauth.AAuthProtocolService;
import org.keycloak.protocol.aauth.representations.AAuthIssuerMetadata;
import org.keycloak.services.Urls;
import org.keycloak.services.resources.RealmsResource;
import org.keycloak.urls.UrlType;
import org.keycloak.wellknown.WellKnownProvider;

import jakarta.ws.rs.core.UriBuilder;
import jakarta.ws.rs.core.UriInfo;

import java.net.URI;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;

/**
 * Well-known provider for AAuth Issuer Metadata.
 * 
 * Implements `/.well-known/aauth-issuer` endpoint per AAuth specification Section 8.2.
 */
public class AAuthIssuerWellKnownProvider implements WellKnownProvider {

    private final KeycloakSession session;

    public AAuthIssuerWellKnownProvider(KeycloakSession session) {
        this.session = session;
    }

    @Override
    public Object getConfig() {
        UriInfo frontendUriInfo = session.getContext().getUri(UrlType.FRONTEND);
        UriInfo backendUriInfo = session.getContext().getUri(UrlType.BACKEND);

        RealmModel realm = session.getContext().getRealm();

        UriBuilder frontendUriBuilder = RealmsResource.protocolUrl(frontendUriInfo);
        UriBuilder backendUriBuilder = RealmsResource.protocolUrl(backendUriInfo);

        AAuthIssuerMetadata metadata = new AAuthIssuerMetadata();

        // Set issuer
        metadata.setIssuer(Urls.realmIssuer(frontendUriInfo.getBaseUri(), realm.getName()));

        // Set JWKS URI
        URI jwksUri = backendUriBuilder.clone()
                .path(AAuthProtocolService.class, "certs")
                .build(realm.getName(), "aauth");
        metadata.setJwksUri(jwksUri.toString());

        // Set agent token endpoint
        URI agentTokenEndpoint = backendUriBuilder.clone()
                .path(AAuthProtocolService.class, "agentToken")
                .build(realm.getName(), "aauth");
        metadata.setAgentTokenEndpoint(agentTokenEndpoint.toString());

        // Set agent auth endpoint (Phase 3)
        URI agentAuthEndpoint = frontendUriBuilder.clone()
                .path(AAuthProtocolService.class, "agentAuth")
                .build(realm.getName(), "aauth");
        metadata.setAgentAuthEndpoint(agentAuthEndpoint.toString());

        // Set supported signing algorithms (from realm key providers)
        metadata.setAgentSigningAlgsSupported(getSupportedSigningAlgorithms(realm));

        // Set supported request types
        metadata.setRequestTypesSupported(Arrays.asList("auth", "code", "refresh", "exchange"));

        // Set supported scopes (optional - can be enhanced later)
        metadata.setScopesSupported(getSupportedScopes(realm));

        return metadata;
    }

    /**
     * Get supported signing algorithms from realm key providers.
     */
    private List<String> getSupportedSigningAlgorithms(RealmModel realm) {
        List<String> algorithms = new ArrayList<>();
        
        // Check what key types are available in the realm
        session.keys().getKeysStream(realm)
                .filter(k -> k.getStatus().isEnabled())
                .forEach(k -> {
                    String alg = k.getAlgorithmOrDefault();
                    if (alg != null && !algorithms.contains(alg)) {
                        // Map Keycloak algorithm names to AAuth algorithm names
                        if (alg.startsWith("EdDSA")) {
                            // Check curve for EdDSA
                            if (k.getCurve() != null) {
                                if ("Ed25519".equals(k.getCurve())) {
                                    if (!algorithms.contains("Ed25519")) {
                                        algorithms.add("Ed25519");
                                    }
                                } else if ("Ed448".equals(k.getCurve())) {
                                    if (!algorithms.contains("Ed448")) {
                                        algorithms.add("Ed448");
                                    }
                                }
                            }
                        } else if (alg.startsWith("RS") || alg.startsWith("PS")) {
                            if (!algorithms.contains(alg)) {
                                algorithms.add(alg);
                            }
                        } else if (alg.startsWith("ES")) {
                            if (!algorithms.contains(alg)) {
                                algorithms.add(alg);
                            }
                        }
                    }
                });

        // Default algorithms if none found
        if (algorithms.isEmpty()) {
            algorithms.add("Ed25519");
            algorithms.add("RS256");
            algorithms.add("ES256");
        }

        return algorithms;
    }

    /**
     * Get supported scopes from realm client scopes.
     */
    private List<String> getSupportedScopes(RealmModel realm) {
        List<String> scopes = new ArrayList<>();
        
        realm.getClientScopesStream()
                .filter(scope -> "aauth".equals(scope.getProtocol()))
                .forEach(scope -> scopes.add(scope.getName()));

        return scopes;
    }

    @Override
    public void close() {
        // No cleanup needed
    }
}

