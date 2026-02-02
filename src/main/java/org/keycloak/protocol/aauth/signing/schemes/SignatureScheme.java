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

import org.keycloak.protocol.aauth.signing.SignatureKeyParser;

import java.security.PublicKey;

/**
 * Interface for signature scheme handlers that discover public keys based on the Signature-Key header scheme.
 * 
 * Each scheme (hwk, jwks, x509, jwt) has its own implementation that handles key discovery.
 */
public interface SignatureScheme {

    /**
     * Discover the public key based on the Signature-Key header parameters.
     * 
     * @param keyParser The parsed Signature-Key header
     * @return The public key for signature verification
     * @throws Exception If key discovery fails
     */
    PublicKey discoverPublicKey(SignatureKeyParser keyParser) throws Exception;

    /**
     * Get the signature algorithm to use for verification.
     * 
     * @param keyParser The parsed Signature-Key header
     * @return The algorithm name (e.g., "Ed25519", "RS256")
     */
    String getAlgorithm(SignatureKeyParser keyParser);

    /**
     * Get the agent identifier from the signature scheme.
     * 
     * @param keyParser The parsed Signature-Key header
     * @return The agent identifier (HTTPS URL), or null for pseudonymous schemes
     */
    String getAgentId(SignatureKeyParser keyParser);
}

