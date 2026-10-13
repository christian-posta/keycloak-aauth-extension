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

import org.junit.jupiter.api.Nested;
import org.junit.jupiter.api.Test;
import org.keycloak.models.RealmModel;

import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.when;

/**
 * Exercises the configuration examples documented in the README
 * ("AAuth Scopes That Trigger User Consent" and "Realm Attributes").
 */
class AAuthConfigReadmeExamplesTest {

    private AAuthConfig configWith(String... attributes) {
        RealmModel realm = mock(RealmModel.class);
        for (int i = 0; i < attributes.length; i += 2) {
            when(realm.getAttribute(attributes[i])).thenReturn(attributes[i + 1]);
        }
        return AAuthConfig.forRealm(realm);
    }

    @Nested
    class ConsentScopeDefaults {

        // README: "Default behavior: When both attributes are not set ...
        // Exact matches: openid, profile, email; Prefixes: user., profile., email."
        @Test
        void defaultExactMatchesRequireConsent() {
            AAuthConfig config = configWith();
            assertTrue(config.isConsentRequiredForScope("openid"));
            assertTrue(config.isConsentRequiredForScope("profile"));
            assertTrue(config.isConsentRequiredForScope("email"));
        }

        // README example: scope=user.preferences → request_token (prefix match)
        @Test
        void defaultPrefixesRequireConsent() {
            AAuthConfig config = configWith();
            assertTrue(config.isConsentRequiredForScope("user.preferences"));
            assertTrue(config.isConsentRequiredForScope("profile.read"));
            assertTrue(config.isConsentRequiredForScope("email.send"));
        }

        // README example: scope=data.read → auth_token (no match, direct grant)
        @Test
        void unmatchedScopeIsDirectGrant() {
            AAuthConfig config = configWith();
            assertFalse(config.isConsentRequiredForScope("data.read"));
        }
    }

    @Nested
    class ConsentScopeConfiguration {

        // README example configuration:
        // aauth.consent.required.scopes = ["openid","profile","email","calendar.read"]
        // aauth.consent.required.scope.prefixes = ["user.","profile.","email."]
        @Test
        void configuredScopesAndPrefixesAreApplied() {
            AAuthConfig config = configWith(
                    AAuthConfig.CONSENT_REQUIRED_SCOPES, "[\"openid\",\"profile\",\"email\",\"calendar.read\"]",
                    AAuthConfig.CONSENT_REQUIRED_SCOPE_PREFIXES, "[\"user.\",\"profile.\",\"email.\"]");

            assertTrue(config.isConsentRequiredForScope("calendar.read"));
            assertTrue(config.isConsentRequiredForScope("openid"));
            assertTrue(config.isConsentRequiredForScope("user.preferences"));
            assertFalse(config.isConsentRequiredForScope("data.read"));
        }

        // README: "Once you set either attribute (even to []), the system uses
        // only your configured lists and does not apply defaults."
        @Test
        void configuredListsReplaceDefaults() {
            AAuthConfig config = configWith(
                    AAuthConfig.CONSENT_REQUIRED_SCOPE_PREFIXES, "[\"api.\"]");

            assertTrue(config.isConsentRequiredForScope("api.write"));
            // Defaults no longer apply once a list is configured
            assertFalse(config.isConsentRequiredForScope("openid"));
            assertFalse(config.isConsentRequiredForScope("user.preferences"));
        }

        // README: "To restore defaults, remove the attributes entirely."
        @Test
        void removingAttributesRestoresDefaults() {
            AAuthConfig config = configWith(
                    AAuthConfig.CONSENT_REQUIRED_SCOPES, "",
                    AAuthConfig.CONSENT_REQUIRED_SCOPE_PREFIXES, "");

            assertTrue(config.isConsentRequiredForScope("openid"));
            assertTrue(config.isConsentRequiredForScope("user.preferences"));
        }
    }

    @Nested
    class RealmAttributes {

        // README: aauth.enabled - Enable/disable AAuth protocol
        // (note: the implementation defaults to enabled when the attribute is not set)
        @Test
        void enabledAttribute() {
            assertTrue(configWith().isEnabled());
            assertTrue(configWith(AAuthConfig.ENABLED, "true").isEnabled());
            assertFalse(configWith(AAuthConfig.ENABLED, "false").isEnabled());
        }

        // README: aauth.allowed.agents - list of allowed agent IDs
        // (stored as a JSON array realm attribute)
        @Test
        void allowedAgents() {
            AAuthConfig config = configWith(
                    AAuthConfig.ALLOWED_AGENTS, "[\"https://agent.example.com\"]");

            assertTrue(config.isAgentAllowed("https://agent.example.com"));
            assertFalse(config.isAgentAllowed("https://other.example.com"));

            // No allowlist configured = all agents allowed
            assertTrue(configWith().isAgentAllowed("https://any.example.com"));
        }

        @Test
        void blockedAgentsWinOverAllowlist() {
            AAuthConfig config = configWith(
                    AAuthConfig.ALLOWED_AGENTS, "[\"https://agent.example.com\"]",
                    AAuthConfig.BLOCKED_AGENTS, "[\"https://agent.example.com\"]");

            assertFalse(config.isAgentAllowed("https://agent.example.com"));
        }

        // README: aauth.allowed.scopes - list of allowed scopes
        // README direct grant example requests: scope=read write
        @Test
        void allowedScopes() {
            AAuthConfig config = configWith(
                    AAuthConfig.ALLOWED_SCOPES, "[\"read\",\"write\"]");

            assertTrue(config.areScopesAllowed("read write"));
            assertFalse(config.areScopesAllowed("read admin"));

            // No restriction configured = all scopes allowed
            assertTrue(configWith().areScopesAllowed("read write"));
        }
    }
}
