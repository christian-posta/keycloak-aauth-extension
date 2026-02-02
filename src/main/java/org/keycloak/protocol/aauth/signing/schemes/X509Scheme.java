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

import org.jboss.logging.Logger;
import org.keycloak.common.util.PemUtils;
import org.keycloak.models.KeycloakSession;
import org.keycloak.protocol.aauth.signing.SignatureKeyParser;
import org.keycloak.protocol.aauth.signing.exceptions.SignatureVerificationException;

import java.security.PublicKey;
import java.security.cert.X509Certificate;

/**
 * Signature scheme handler for scheme=x509.
 * 
 * Fetches X.509 certificate from x5u URL and validates it, then extracts the public key.
 */
public class X509Scheme implements SignatureScheme {

    private static final Logger logger = Logger.getLogger(X509Scheme.class);
    private final KeycloakSession session;

    public X509Scheme(KeycloakSession session) {
        this.session = session;
    }

    @Override
    public PublicKey discoverPublicKey(SignatureKeyParser keyParser) throws Exception {
        String x5u = keyParser.getX5u();
        String x5t = keyParser.getX5t();
        
        if (x5u == null) {
            throw new SignatureVerificationException("Missing 'x5u' parameter in Signature-Key for scheme=x509");
        }

        // Fetch certificate from x5u URL
        String pemCert = session.getProvider(org.keycloak.connections.httpclient.HttpClientProvider.class)
                .getString(x5u);

        if (pemCert == null || pemCert.trim().isEmpty()) {
            throw new SignatureVerificationException("Failed to fetch certificate from x5u: " + x5u);
        }

        // Parse PEM certificate
        X509Certificate certificate = PemUtils.decodeCertificate(pemCert);
        
        // Validate certificate (basic checks - expiration, chain validation would be done separately)
        certificate.checkValidity();
        
        // Verify thumbprint if provided
        if (x5t != null) {
            // Calculate SHA-256 thumbprint and compare
            // This is a simplified check - full validation would verify the thumbprint
            logger.debugf("x5t thumbprint provided: %s (validation TBD)", x5t);
        }

        return certificate.getPublicKey();
    }

    @Override
    public String getAlgorithm(SignatureKeyParser keyParser) {
        // Algorithm should be determined from certificate, default to RS256 for RSA certs
        // This will be enhanced when we parse the actual certificate
        return "RS256"; // Default, should be determined from certificate
    }

    @Override
    public String getAgentId(SignatureKeyParser keyParser) {
        // X.509 scheme can identify agent via certificate subject/issuer
        // For now, return null - this could be enhanced to extract from certificate
        return null;
    }
}

