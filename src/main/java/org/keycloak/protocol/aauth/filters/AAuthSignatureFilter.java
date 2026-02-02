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

package org.keycloak.protocol.aauth.filters;

import org.jboss.logging.Logger;
import org.keycloak.http.HttpRequest;
import org.keycloak.models.KeycloakSession;
import org.keycloak.protocol.aauth.signing.HTTPSigVerifier;
import org.keycloak.protocol.aauth.signing.exceptions.SignatureVerificationException;
import org.keycloak.utils.KeycloakSessionUtil;

import jakarta.annotation.Priority;
import jakarta.ws.rs.container.ContainerRequestContext;
import jakarta.ws.rs.container.ContainerRequestFilter;
import jakarta.ws.rs.core.Response;
import jakarta.ws.rs.ext.Provider;

import java.io.ByteArrayInputStream;
import java.io.IOException;
import java.io.InputStream;

/**
 * Request filter to verify HTTP Message Signatures for AAuth protocol endpoints.
 * 
 * This filter only applies to requests to AAuth protocol endpoints (/protocol/aauth/).
 * It verifies the HTTP Message Signature and stores the agent identity in the request context
 * for use by AAuth endpoints.
 * 
 * Priority is set to run after session is available but before authentication flows.
 * Note: Cannot use @PreMatching as session is not available at that time.
 */
@Provider
@Priority(2000) // Run after session setup but before authentication
public class AAuthSignatureFilter implements ContainerRequestFilter {

    private static final Logger logger = Logger.getLogger(AAuthSignatureFilter.class);

    @Override
    public void filter(ContainerRequestContext requestContext) throws IOException {
        // Only process AAuth protocol endpoints
        String path = requestContext.getUriInfo().getPath();
        if (!path.contains("/protocol/aauth/")) {
            return;
        }

        // Skip signature verification for well-known endpoints (they don't require signatures)
        if (path.contains("/.well-known/")) {
            return;
        }

        KeycloakSession session = KeycloakSessionUtil.getKeycloakSession();
        if (session == null) {
            logger.warn("KeycloakSession not available for AAuth signature verification");
            return;
        }

        HttpRequest request = session.getContext().getHttpRequest();
        if (request == null) {
            logger.warn("HttpRequest not available for AAuth signature verification");
            return;
        }

        // Check if Signature-Key header is present
        String signatureKey = request.getHttpHeaders().getHeaderString("Signature-Key");
        logger.infof("AAuthSignatureFilter: path=%s, Signature-Key present=%s", path, signatureKey != null);
        if (signatureKey == null) {
            // No signature - this might be acceptable for some endpoints, let them handle it
            logger.debug("No Signature-Key header present for AAuth endpoint");
            return;
        }

        try {
            // Buffer body if Content-Digest is present (needed for validation per RFC 9421 Section 7.2.8)
            byte[] bodyBytes = null;
            String contentDigest = request.getHttpHeaders().getHeaderString("Content-Digest");
            
            if (contentDigest != null && !contentDigest.trim().isEmpty()) {
                // Content-Digest is present, we need to buffer the body for validation
                bodyBytes = bufferRequestBody(requestContext);
                logger.debugf("Buffered request body for Content-Digest validation: %d bytes", 
                    bodyBytes != null ? bodyBytes.length : 0);
            }
            
            // Verify HTTP Message Signature (with body validation if Content-Digest is present)
            HTTPSigVerifier verifier = new HTTPSigVerifier(session);
            HTTPSigVerifier.VerificationResult result = verifier.verify(request, bodyBytes);

            logger.infof("AAuthSignatureFilter: Signature verified, agentId=%s, publicKey=%s, scheme=%s",
                    result.getAgentId(), result.getPublicKey() != null, result.getScheme());

            // Store agent identity in request context for use by endpoints
            requestContext.setProperty("aauth.agent.id", result.getAgentId());
            requestContext.setProperty("aauth.agent.public.key", result.getPublicKey());
            requestContext.setProperty("aauth.signature.scheme", result.getScheme());

            // Also store in session for access by grant types
            session.setAttribute("aauth.agent.id", result.getAgentId());
            session.setAttribute("aauth.agent.public.key", result.getPublicKey());
            session.setAttribute("aauth.signature.scheme", result.getScheme());

            // If scheme=jwt with auth+jwt token, the upstream token is already stored by JWTScheme
            // This is used for token exchange flows (Phase 4)

            logger.debugf("HTTP Message Signature verified for agent: %s", result.getAgentId());

        } catch (SignatureVerificationException e) {
            logger.warnf(e, "HTTP Message Signature verification failed for AAuth endpoint");
            
            // Return 401 with appropriate error
            Response errorResponse = Response.status(Response.Status.UNAUTHORIZED)
                    .entity("{\"error\":\"invalid_signature\",\"error_description\":\"" + e.getMessage() + "\"}")
                    .type("application/json")
                    .build();
            
            requestContext.abortWith(errorResponse);
        }
    }

    /**
     * Buffer the request body so it can be used for Content-Digest validation
     * and still be available for downstream processing.
     * 
     * @param requestContext The container request context
     * @return The buffered body bytes, or null if no body
     * @throws IOException If reading the body fails
     */
    private byte[] bufferRequestBody(ContainerRequestContext requestContext) throws IOException {
        InputStream entityStream = requestContext.getEntityStream();
        if (entityStream == null) {
            return null;
        }
        
        // Read all bytes from the entity stream
        byte[] bodyBytes = entityStream.readAllBytes();
        
        // Reset the entity stream so downstream handlers can read it
        requestContext.setEntityStream(new ByteArrayInputStream(bodyBytes));
        
        return bodyBytes;
    }
}

