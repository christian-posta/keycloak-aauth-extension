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

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import dasniko.testcontainers.keycloak.KeycloakContainer;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.ValueSource;
import org.keycloak.jose.jwk.JWKBuilder;
import org.keycloak.util.JsonSerialization;
import org.testcontainers.junit.jupiter.Container;
import org.testcontainers.junit.jupiter.Testcontainers;

import java.net.CookieHandler;
import java.net.URI;
import java.net.URLEncoder;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import java.nio.charset.StandardCharsets;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.MessageDigest;
import java.security.Signature;
import java.util.Base64;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.regex.Matcher;
import java.util.regex.Pattern;
import java.util.stream.Collectors;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertTrue;

/**
 * Exercises the curl examples from the README against a real Keycloak
 * with the extension deployed as a provider.
 */
@Testcontainers
class ReadmeExamplesIT {

    static final String REALM = "master";

    @Container
    static final KeycloakContainer keycloak = new KeycloakContainer("quay.io/keycloak/keycloak:26.8.1")
            .withProviderClassesFrom("target/classes");

    // HTTP/1.1 so the Host header is sent as a real header: the signed requests cover
    // @authority, which the server resolves from the Host header (with HTTP/2 it would
    // travel as the :authority pseudo-header instead and signature verification fails)
    final HttpClient http = HttpClient.newBuilder().version(HttpClient.Version.HTTP_1_1).build();
    final ObjectMapper mapper = new ObjectMapper();

    String baseUrl() {
        String url = keycloak.getAuthServerUrl();
        return url.endsWith("/") ? url.substring(0, url.length() - 1) : url;
    }

    // README: curl https://keycloak.example.com/realms/{realm}/.well-known/aauth-issuer.json
    @Test
    void wellKnownEndpointServesIssuerMetadata() throws Exception {
        HttpResponse<String> response = http.send(
                HttpRequest.newBuilder(URI.create(baseUrl() + "/realms/" + REALM + "/.well-known/aauth-issuer.json"))
                        .GET().build(),
                HttpResponse.BodyHandlers.ofString());

        assertEquals(200, response.statusCode());

        JsonNode metadata = mapper.readTree(response.body());
        assertEquals(baseUrl() + "/realms/" + REALM, metadata.get("issuer").asText());
        assertTrue(metadata.hasNonNull("jwks_uri"));
        assertTrue(metadata.hasNonNull("agent_token_endpoint"));

        List<String> requestTypes = mapper.convertValue(metadata.get("request_types_supported"),
                mapper.getTypeFactory().constructCollectionType(List.class, String.class));
        // README: grant types auth, code, refresh, exchange
        assertTrue(requestTypes.containsAll(List.of("auth", "code", "refresh", "exchange")),
                "request_types_supported was: " + requestTypes);
    }

    // README: enable AAuth via Admin API:
    // curl -X PUT ".../admin/realms/{realm}" -d '{"attributes": {"aauth.enabled": "true"}}'
    @Test
    void enableAAuthViaAdminApi() throws Exception {
        String token = adminAccessToken();

        HttpResponse<String> update = http.send(
                HttpRequest.newBuilder(URI.create(baseUrl() + "/admin/realms/" + REALM))
                        .header("Authorization", "Bearer " + token)
                        .header("Content-Type", "application/json")
                        .PUT(HttpRequest.BodyPublishers.ofString(
                                "{\"attributes\": {\"aauth.enabled\": \"true\"}}"))
                        .build(),
                HttpResponse.BodyHandlers.ofString());
        assertEquals(204, update.statusCode(), "body: " + update.body());

        HttpResponse<String> realm = http.send(
                HttpRequest.newBuilder(URI.create(baseUrl() + "/admin/realms/" + REALM))
                        .header("Authorization", "Bearer " + token)
                        .GET().build(),
                HttpResponse.BodyHandlers.ofString());
        assertEquals(200, realm.statusCode());
        assertEquals("true", mapper.readTree(realm.body()).path("attributes").path("aauth.enabled").asText());
    }

    // README: direct grant token request against
    // POST /realms/{realm}/protocol/aauth/agent/token
    // Without the HTTPSig signature headers the request must be rejected.
    @Test
    void unsignedTokenRequestIsRejected() throws Exception {
        String form = formEncode(Map.of(
                "request_type", "auth",
                "scope", "read write",
                "resource_id", "https://resource.example.com"));

        HttpResponse<String> response = http.send(
                HttpRequest.newBuilder(URI.create(baseUrl() + "/realms/" + REALM + "/protocol/aauth/agent/token"))
                        .header("Content-Type", "application/x-www-form-urlencoded")
                        .POST(HttpRequest.BodyPublishers.ofString(form))
                        .build(),
                HttpResponse.BodyHandlers.ofString());

        assertEquals(401, response.statusCode(), "body: " + response.body());
        assertEquals("invalid_request", mapper.readTree(response.body()).path("error").asText());
    }

    // README: signed direct grant (no user consent):
    // POST /realms/{realm}/protocol/aauth/agent/token with Signature-Key/Signature-Input/Signature
    // headers and request_type=auth&scope=read write. The scopes do not require consent,
    // so an auth_token is issued directly.
    @Test
    void signedDirectGrantIssuesAuthToken() throws Exception {
        HttpMessageSigner agent = new HttpMessageSigner();
        String form = formEncode(Map.of(
                "request_type", "auth",
                "scope", "read write",
                "resource_id", "https://resource.example.com"));

        HttpResponse<String> response = http.send(
                agent.signedPost(baseUrl() + "/realms/" + REALM + "/protocol/aauth/agent/token", form),
                HttpResponse.BodyHandlers.ofString());

        assertEquals(200, response.statusCode(), "body: " + response.body());
        JsonNode token = mapper.readTree(response.body());
        assertEquals(3, token.get("auth_token").asText().split("\\.").length, "auth_token should be a JWT");
        assertTrue(token.get("expires_in").asInt() > 0);
    }

    // README: user consent flow. A consent-requiring scope (openid) yields a pending
    // request (202) with an interaction code. Step 1 sends the user to
    // GET /realms/{realm}/protocol/aauth/interact?code=... which redirects to the login page.
    @Test
    void signedConsentFlowRedirectsUserToLogin() throws Exception {
        PendingRequest pending = requestConsentScope(new HttpMessageSigner());

        HttpClient browser = newBrowser();
        HttpResponse<String> interaction = browser.send(get(pending.interactUrl()), HttpResponse.BodyHandlers.ofString());

        assertEquals(303, interaction.statusCode(), "body: " + interaction.body());
        String location = interaction.headers().firstValue("Location").orElse("");
        assertTrue(location.contains("/login-actions/authenticate"),
                "expected a redirect to the login page, got: " + location);
        assertTrue(location.contains("tab_id="),
                "login redirect should carry the authentication session tab_id: " + location);
    }

    // README: the complete user consent flow, rendered with the keycloak.v2 (PatternFly 5)
    // and the classic keycloak (PatternFly 3/4) login theme. The consent page must render
    // under both themes: the user logs in, sees the consent page, accepts, and the agent
    // receives the auth token by polling the pending URL (Step 2).
    @ParameterizedTest(name = "loginTheme={0}")
    @ValueSource(strings = {"keycloak.v2", "keycloak"})
    void consentFlowRendersConsentPageAndIssuesTokenAfterAccept(String loginTheme) throws Exception {
        setLoginTheme(loginTheme);

        HttpMessageSigner agent = new HttpMessageSigner();
        PendingRequest pending = requestConsentScope(agent);

        // Agent polls the pending URL: still waiting for the user
        HttpResponse<String> waiting = http.send(get(pending.location()), HttpResponse.BodyHandlers.ofString());
        assertEquals(202, waiting.statusCode(), "body: " + waiting.body());
        assertEquals("pending", mapper.readTree(waiting.body()).get("status").asText());

        // Step 1: the user opens the interaction URL and logs in
        HttpClient browser = newBrowser();
        String consentPage = loginAndOpenConsentPage(browser, pending.interactUrl());

        assertFalse(consentPage.contains("Failed to render consent screen"), "consent page: " + consentPage);
        assertTrue(consentPage.contains("Agent Authorization Request"), "consent page: " + consentPage);
        assertTrue(consentPage.contains("pseudonymous:"), "consent page should name the agent: " + consentPage);
        assertTrue(consentPage.contains("<span>openid</span>"), "consent page should list the scope: " + consentPage);
        assertTrue(consentPage.contains("id=\"kc-login\""), "consent page should offer an accept button: " + consentPage);
        assertTrue(consentPage.contains("id=\"kc-cancel\""), "consent page should offer a cancel button: " + consentPage);
        String expectedButtonClass = "keycloak".equals(loginTheme) ? "pf-c-button" : "pf-v5-c-button";
        assertTrue(consentPage.contains(expectedButtonClass),
                "consent page should be styled by the " + loginTheme + " theme: " + consentPage);

        // The user accepts
        String consentAction = attribute(consentPage, "<form[^>]*action=\"([^\"]*/protocol/aauth/interact/consent)\"");
        String consentCode = attribute(consentPage, "name=\"consent_code\" value=\"([^\"]+)\"");
        HttpResponse<String> accepted = browser.send(
                HttpRequest.newBuilder(URI.create(consentAction))
                        .header("Content-Type", "application/x-www-form-urlencoded")
                        .POST(HttpRequest.BodyPublishers.ofString(formEncode(Map.of(
                                "consent_code", consentCode,
                                "accept", "Yes"))))
                        .build(),
                HttpResponse.BodyHandlers.ofString());
        assertEquals(303, accepted.statusCode(), "body: " + accepted.body());
        assertTrue(accepted.headers().firstValue("Location").orElse("").startsWith(CALLBACK_URL),
                "after consent the user agent is sent to the redirect_uri: " + accepted.headers());

        // Step 2: the agent polls the pending URL and receives the auth token
        HttpResponse<String> completed = http.send(get(pending.location()), HttpResponse.BodyHandlers.ofString());
        assertEquals(200, completed.statusCode(), "body: " + completed.body());
        JsonNode token = mapper.readTree(completed.body());
        assertEquals(3, token.get("auth_token").asText().split("\\.").length, "auth_token should be a JWT");
        assertTrue(token.get("expires_in").asInt() > 0);
    }

    // The user may also deny the request; the agent then gets access_denied when polling.
    @Test
    void consentFlowDeniedByUserRejectsPendingRequest() throws Exception {
        setLoginTheme("keycloak.v2");

        PendingRequest pending = requestConsentScope(new HttpMessageSigner());
        HttpClient browser = newBrowser();
        String consentPage = loginAndOpenConsentPage(browser, pending.interactUrl());

        String consentAction = attribute(consentPage, "<form[^>]*action=\"([^\"]*/protocol/aauth/interact/consent)\"");
        String consentCode = attribute(consentPage, "name=\"consent_code\" value=\"([^\"]+)\"");
        HttpResponse<String> denied = browser.send(
                HttpRequest.newBuilder(URI.create(consentAction))
                        .header("Content-Type", "application/x-www-form-urlencoded")
                        .POST(HttpRequest.BodyPublishers.ofString(formEncode(Map.of(
                                "consent_code", consentCode,
                                "cancel", "No"))))
                        .build(),
                HttpResponse.BodyHandlers.ofString());
        assertTrue(denied.statusCode() == 303 || denied.statusCode() == 200, "status: " + denied.statusCode());

        HttpResponse<String> result = http.send(get(pending.location()), HttpResponse.BodyHandlers.ofString());
        assertEquals(403, result.statusCode(), "body: " + result.body());
        assertEquals("access_denied", mapper.readTree(result.body()).get("error").asText());
    }

    // An unknown interaction code must not start a consent flow.
    @Test
    void interactionEndpointRejectsUnknownCode() throws Exception {
        HttpResponse<String> response = http.send(
                HttpRequest.newBuilder(URI.create(baseUrl() + "/realms/" + REALM
                                + "/protocol/aauth/agent/auth?code=bogus-interaction-code"))
                        .GET().build(),
                HttpResponse.BodyHandlers.ofString());

        assertEquals(400, response.statusCode());
        assertTrue(response.body().contains("Invalid or expired interaction code"),
                "body: " + response.body());
    }

    // README: request_type=code selects the authorization code request type.
    // An unknown code must be rejected with invalid_grant.
    @Test
    void signedCodeExchangeRejectsUnknownCode() throws Exception {
        HttpMessageSigner agent = new HttpMessageSigner();
        String form = formEncode(Map.of(
                "request_type", "code",
                "code", "bogus-authorization-code"));

        HttpResponse<String> response = http.send(
                agent.signedPost(baseUrl() + "/realms/" + REALM + "/protocol/aauth/agent/token", form),
                HttpResponse.BodyHandlers.ofString());

        assertEquals(400, response.statusCode(), "body: " + response.body());
        assertEquals("invalid_grant", mapper.readTree(response.body()).path("error").asText(),
                "body: " + response.body());
    }

    static final String CALLBACK_URL = "https://agent.example.com/callback";

    record PendingRequest(String location, String interactionCode, String interactUrl) {}

    /** Signed token request for a consent-requiring scope; returns the 202 pending request. */
    private PendingRequest requestConsentScope(HttpMessageSigner agent) throws Exception {
        String form = formEncode(Map.of(
                "request_type", "auth",
                "scope", "openid",
                "redirect_uri", CALLBACK_URL));

        HttpResponse<String> pending = http.send(
                agent.signedPost(baseUrl() + "/realms/" + REALM + "/protocol/aauth/agent/token", form),
                HttpResponse.BodyHandlers.ofString());

        assertEquals(202, pending.statusCode(), "body: " + pending.body());
        JsonNode body = mapper.readTree(pending.body());
        assertEquals("pending", body.get("status").asText());
        assertEquals("interaction", body.get("require").asText());
        String interactionCode = body.get("code").asText();
        assertFalse(interactionCode.isEmpty());
        String location = body.get("location").asText();
        assertTrue(location.startsWith(baseUrl() + "/realms/" + REALM + "/protocol/aauth/pending/"),
                "location: " + location);

        return new PendingRequest(location, interactionCode,
                baseUrl() + "/realms/" + REALM + "/protocol/aauth/interact?code=" + interactionCode);
    }

    /**
     * Drives a browser through the interaction URL: follow the redirect to the login page,
     * submit the admin credentials, follow the redirect back and return the consent page HTML.
     */
    private String loginAndOpenConsentPage(HttpClient browser, String interactUrl) throws Exception {
        HttpResponse<String> interaction = browser.send(get(interactUrl), HttpResponse.BodyHandlers.ofString());
        assertEquals(303, interaction.statusCode(), "body: " + interaction.body());
        String loginUrl = interaction.headers().firstValue("Location").orElseThrow();

        HttpResponse<String> loginPage = browser.send(get(loginUrl), HttpResponse.BodyHandlers.ofString());
        assertEquals(200, loginPage.statusCode(), "body: " + loginPage.body());
        String loginAction = attribute(loginPage.body(), "<form[^>]*id=\"kc-form-login\"[^>]*action=\"([^\"]+)\"");

        HttpResponse<String> loggedIn = browser.send(
                HttpRequest.newBuilder(URI.create(loginAction))
                        .header("Content-Type", "application/x-www-form-urlencoded")
                        .POST(HttpRequest.BodyPublishers.ofString(formEncode(Map.of(
                                "username", keycloak.getAdminUsername(),
                                "password", keycloak.getAdminPassword(),
                                "credentialId", ""))))
                        .build(),
                HttpResponse.BodyHandlers.ofString());
        assertTrue(loggedIn.statusCode() == 302 || loggedIn.statusCode() == 303,
                "login should redirect back to the interaction endpoint, status=" + loggedIn.statusCode()
                        + " body: " + loggedIn.body());
        String backToInteract = loggedIn.headers().firstValue("Location").orElseThrow();
        assertTrue(backToInteract.contains("/protocol/aauth/interact"), "location: " + backToInteract);

        HttpResponse<String> consent = browser.send(get(backToInteract), HttpResponse.BodyHandlers.ofString());
        assertEquals(200, consent.statusCode(), "body: " + consent.body());
        return consent.body();
    }

    private void setLoginTheme(String loginTheme) throws Exception {
        HttpResponse<String> update = http.send(
                HttpRequest.newBuilder(URI.create(baseUrl() + "/admin/realms/" + REALM))
                        .header("Authorization", "Bearer " + adminAccessToken())
                        .header("Content-Type", "application/json")
                        .PUT(HttpRequest.BodyPublishers.ofString("{\"loginTheme\": \"" + loginTheme + "\"}"))
                        .build(),
                HttpResponse.BodyHandlers.ofString());
        assertEquals(204, update.statusCode(), "body: " + update.body());
    }

    private static HttpClient newBrowser() {
        return HttpClient.newBuilder()
                .version(HttpClient.Version.HTTP_1_1)
                .followRedirects(HttpClient.Redirect.NEVER)
                .cookieHandler(new BrowserCookieJar())
                .build();
    }

    /**
     * Cookie jar that behaves like a browser on localhost. The JDK CookieManager cannot be
     * used here: it rejects cookies from hosts without a dot (localhost) and never sends
     * "Secure" cookies over plain http, but Keycloak always marks its session cookies
     * SameSite=None; Secure (browsers treat localhost as a secure context).
     */
    static class BrowserCookieJar extends CookieHandler {

        private final Map<String, String> cookies = new LinkedHashMap<>();

        @Override
        public synchronized Map<String, List<String>> get(URI uri, Map<String, List<String>> requestHeaders) {
            if (cookies.isEmpty()) {
                return Map.of();
            }
            String header = cookies.entrySet().stream()
                    .map(e -> e.getKey() + "=" + e.getValue())
                    .collect(Collectors.joining("; "));
            return Map.of("Cookie", List.of(header));
        }

        @Override
        public synchronized void put(URI uri, Map<String, List<String>> responseHeaders) {
            for (Map.Entry<String, List<String>> header : responseHeaders.entrySet()) {
                if (header.getKey() == null || !header.getKey().equalsIgnoreCase("Set-Cookie")) {
                    continue;
                }
                for (String setCookie : header.getValue()) {
                    String[] attributes = setCookie.split(";");
                    int eq = attributes[0].indexOf('=');
                    if (eq <= 0) {
                        continue;
                    }
                    String name = attributes[0].substring(0, eq).trim();
                    String value = attributes[0].substring(eq + 1).trim();
                    boolean expired = false;
                    for (int i = 1; i < attributes.length; i++) {
                        if (attributes[i].trim().equalsIgnoreCase("Max-Age=0")) {
                            expired = true;
                        }
                    }
                    if (expired || value.isEmpty()) {
                        cookies.remove(name);
                    } else {
                        cookies.put(name, value);
                    }
                }
            }
        }
    }

    private static HttpRequest get(String url) {
        return HttpRequest.newBuilder(URI.create(url)).GET().build();
    }

    /** Extracts the first capture group of the pattern from HTML, unescaping &amp;. */
    private static String attribute(String html, String regex) {
        Matcher m = Pattern.compile(regex).matcher(html);
        assertTrue(m.find(), "pattern " + regex + " not found in: " + html);
        String value = m.group(1);
        assertNotNull(value);
        return value.replace("&amp;", "&");
    }

    /**
     * Minimal RFC 9421 HTTP Message Signatures client using the AAuth "hwk" scheme:
     * an Ed25519 key carried directly in the Signature-Key header (pseudonymous agent).
     * The signature base mirrors the server-side SignatureBaseBuilder.
     */
    static class HttpMessageSigner {

        private static final String LABEL = "sig";
        private static final List<String> COMPONENTS = List.of(
                "@method", "@authority", "@path", "content-type", "content-digest", "signature-key");

        private final KeyPair keyPair;
        private final String signatureKeyHeader;

        HttpMessageSigner() throws Exception {
            this.keyPair = KeyPairGenerator.getInstance("Ed25519").generateKeyPair();
            JsonNode jwk = new ObjectMapper().readTree(
                    JsonSerialization.writeValueAsString(JWKBuilder.create().okp(keyPair.getPublic())));
            this.signatureKeyHeader = LABEL + "=hwk;kty=\"OKP\";crv=\"Ed25519\";x=\"" + jwk.get("x").asText() + "\"";
        }

        HttpRequest signedPost(String url, String form) throws Exception {
            URI uri = URI.create(url);
            byte[] body = form.getBytes(StandardCharsets.UTF_8);
            String contentType = "application/x-www-form-urlencoded";
            String contentDigest = "sha-256=:"
                    + Base64.getEncoder().encodeToString(MessageDigest.getInstance("SHA-256").digest(body)) + ":";

            long created = System.currentTimeMillis() / 1000;
            String signatureParams = COMPONENTS.stream()
                    .map(c -> "\"" + c + "\"")
                    .collect(Collectors.joining(" ", "(", ")")) + ";created=" + created;

            String authority = uri.getHost() + (uri.getPort() > 0 ? ":" + uri.getPort() : "");
            Map<String, String> componentValues = Map.of(
                    "@method", "POST",
                    "@authority", authority,
                    "@path", uri.getPath(),
                    "content-type", contentType,
                    "content-digest", contentDigest,
                    "signature-key", signatureKeyHeader);

            String signatureBase = COMPONENTS.stream()
                    .map(c -> "\"" + c + "\": " + componentValues.get(c))
                    .collect(Collectors.joining("\n"))
                    + "\n\"@signature-params\": " + signatureParams;

            Signature signer = Signature.getInstance("Ed25519");
            signer.initSign(keyPair.getPrivate());
            signer.update(signatureBase.getBytes(StandardCharsets.UTF_8));
            String signature = Base64.getEncoder().encodeToString(signer.sign());

            return HttpRequest.newBuilder(uri)
                    .header("Content-Type", contentType)
                    .header("Content-Digest", contentDigest)
                    .header("Signature-Key", signatureKeyHeader)
                    .header("Signature-Input", LABEL + "=" + signatureParams)
                    .header("Signature", LABEL + "=:" + signature + ":")
                    .POST(HttpRequest.BodyPublishers.ofByteArray(body))
                    .build();
        }
    }

    private String adminAccessToken() throws Exception {
        String form = formEncode(Map.of(
                "grant_type", "password",
                "client_id", "admin-cli",
                "username", keycloak.getAdminUsername(),
                "password", keycloak.getAdminPassword()));

        HttpResponse<String> response = http.send(
                HttpRequest.newBuilder(URI.create(baseUrl() + "/realms/master/protocol/openid-connect/token"))
                        .header("Content-Type", "application/x-www-form-urlencoded")
                        .POST(HttpRequest.BodyPublishers.ofString(form))
                        .build(),
                HttpResponse.BodyHandlers.ofString());
        assertEquals(200, response.statusCode(), "body: " + response.body());
        return mapper.readTree(response.body()).get("access_token").asText();
    }

    private static String formEncode(Map<String, String> params) {
        return params.entrySet().stream()
                .map(e -> e.getKey() + "=" + URLEncoder.encode(e.getValue(), StandardCharsets.UTF_8))
                .collect(Collectors.joining("&"));
    }
}
