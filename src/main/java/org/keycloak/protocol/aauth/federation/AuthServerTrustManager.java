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

import org.jboss.logging.Logger;
import org.keycloak.models.KeycloakSession;
import org.keycloak.models.RealmModel;
import org.keycloak.util.JsonSerialization;

import java.util.ArrayList;
import java.util.HashSet;
import java.util.List;
import java.util.Set;

/**
 * Manages trust relationships with upstream AAuth auth servers.
 * 
 * Stores trusted issuer URLs per realm and validates issuer trust
 * before accepting upstream tokens in token exchange flows.
 * 
 * Trust relationships are stored as realm attributes.
 */
public class AuthServerTrustManager {

    private static final Logger logger = Logger.getLogger(AuthServerTrustManager.class);
    
    /**
     * Realm attribute key for storing trusted issuer URLs.
     * Value is a JSON array of issuer URLs.
     */
    private static final String TRUSTED_ISSUERS_ATTRIBUTE = "aauth.trusted.issuers";

    private final RealmModel realm;

    public AuthServerTrustManager(KeycloakSession session, RealmModel realm) {
        this.realm = realm;
    }

    /**
     * Check if an issuer is trusted.
     * 
     * @param issuer The issuer URL to check
     * @return true if the issuer is trusted, false otherwise
     */
    public boolean isTrusted(String issuer) {
        if (issuer == null || issuer.isEmpty()) {
            return false;
        }

        Set<String> trustedIssuers = getTrustedIssuers();
        return trustedIssuers.contains(issuer);
    }

    /**
     * Add a trusted issuer.
     * 
     * @param issuer The issuer URL to trust
     */
    public void addTrustedIssuer(String issuer) {
        if (issuer == null || issuer.isEmpty()) {
            throw new IllegalArgumentException("Issuer cannot be null or empty");
        }

        Set<String> trustedIssuers = getTrustedIssuers();
        trustedIssuers.add(issuer);
        saveTrustedIssuers(trustedIssuers);
        
        logger.debugf("Added trusted issuer: %s for realm: %s", issuer, realm.getName());
    }

    /**
     * Remove a trusted issuer.
     * 
     * @param issuer The issuer URL to remove from trust list
     */
    public void removeTrustedIssuer(String issuer) {
        if (issuer == null || issuer.isEmpty()) {
            return;
        }

        Set<String> trustedIssuers = getTrustedIssuers();
        if (trustedIssuers.remove(issuer)) {
            saveTrustedIssuers(trustedIssuers);
            logger.debugf("Removed trusted issuer: %s for realm: %s", issuer, realm.getName());
        }
    }

    /**
     * Get all trusted issuers.
     * 
     * @return Set of trusted issuer URLs
     */
    public Set<String> getTrustedIssuers() {
        String attributeValue = realm.getAttribute(TRUSTED_ISSUERS_ATTRIBUTE);
        
        if (attributeValue == null || attributeValue.isEmpty()) {
            return new HashSet<>();
        }

        try {
            // Parse JSON array
            @SuppressWarnings("unchecked")
            List<String> issuers = JsonSerialization.readValue(attributeValue, List.class);
            return new HashSet<>(issuers);
        } catch (Exception e) {
            logger.warnf(e, "Failed to parse trusted issuers attribute for realm: %s", realm.getName());
            // Try comma-separated format for backward compatibility
            return parseCommaSeparated(attributeValue);
        }
    }

    /**
     * Set all trusted issuers (replaces existing list).
     * 
     * @param issuers Set of trusted issuer URLs
     */
    public void setTrustedIssuers(Set<String> issuers) {
        saveTrustedIssuers(issuers);
    }

    /**
     * Save trusted issuers to realm attributes.
     */
    private void saveTrustedIssuers(Set<String> issuers) {
        if (issuers == null || issuers.isEmpty()) {
            realm.removeAttribute(TRUSTED_ISSUERS_ATTRIBUTE);
            return;
        }

        try {
            // Store as JSON array
            List<String> issuerList = new ArrayList<>(issuers);
            String jsonValue = JsonSerialization.writeValueAsString(issuerList);
            realm.setAttribute(TRUSTED_ISSUERS_ATTRIBUTE, jsonValue);
        } catch (Exception e) {
            logger.errorf(e, "Failed to save trusted issuers for realm: %s", realm.getName());
            throw new RuntimeException("Failed to save trusted issuers", e);
        }
    }

    /**
     * Parse comma-separated issuer list (backward compatibility).
     */
    private Set<String> parseCommaSeparated(String value) {
        Set<String> issuers = new HashSet<>();
        if (value != null && !value.isEmpty()) {
            String[] parts = value.split(",");
            for (String part : parts) {
                String trimmed = part.trim();
                if (!trimmed.isEmpty()) {
                    issuers.add(trimmed);
                }
            }
        }
        return issuers;
    }

    /**
     * Validate that an issuer is trusted, throwing an exception if not.
     * 
     * @param issuer The issuer URL to validate
     * @throws IllegalArgumentException If issuer is not trusted
     */
    public void validateTrust(String issuer) {
        if (!isTrusted(issuer)) {
            throw new IllegalArgumentException("Issuer is not trusted: " + issuer);
        }
    }
}

