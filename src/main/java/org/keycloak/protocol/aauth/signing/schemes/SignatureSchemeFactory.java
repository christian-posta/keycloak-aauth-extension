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

import org.keycloak.models.KeycloakSession;
import org.keycloak.protocol.aauth.signing.SignatureKeyParser;
import org.keycloak.protocol.aauth.signing.exceptions.SignatureVerificationException;

/**
 * Factory for creating signature scheme handlers based on the scheme in Signature-Key header.
 */
public class SignatureSchemeFactory {

    /**
     * Create a signature scheme handler based on the parsed Signature-Key header.
     * 
     * @param session The Keycloak session
     * @param keyParser The parsed Signature-Key header
     * @return The appropriate signature scheme handler
     * @throws SignatureVerificationException If the scheme is not supported
     */
    public static SignatureScheme create(KeycloakSession session, SignatureKeyParser keyParser) 
            throws SignatureVerificationException {
        
        String scheme = keyParser.getScheme();
        
        switch (scheme) {
            case "hwk":
                return new HeaderWebKeyScheme();
                
            case "jwks":
                return new JWKSScheme(session);
                
            case "x509":
                return new X509Scheme(session);
                
            case "jwt":
                return new JWTScheme(session);
                
            default:
                throw new SignatureVerificationException("Unsupported signature scheme: " + scheme);
        }
    }
}

