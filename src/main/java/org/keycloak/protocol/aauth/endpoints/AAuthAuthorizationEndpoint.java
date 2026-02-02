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

package org.keycloak.protocol.aauth.endpoints;

import org.jboss.logging.Logger;
import org.keycloak.OAuthErrorException;
import org.keycloak.common.ClientConnection;
import org.keycloak.common.util.Time;
import org.keycloak.events.Details;
import org.keycloak.events.EventBuilder;
import org.keycloak.events.EventType;
import org.keycloak.forms.login.freemarker.model.RealmBean;
import org.keycloak.forms.login.freemarker.model.UrlBean;
import org.keycloak.models.ClientModel;
import org.keycloak.models.KeycloakSession;
import org.keycloak.models.RealmModel;
import org.keycloak.models.UserModel;
import org.keycloak.models.UserSessionModel;
import org.keycloak.protocol.aauth.forms.AAuthConsentBean;
import org.keycloak.protocol.aauth.storage.AAuthAuthorizationCode;
import org.keycloak.protocol.aauth.storage.AAuthRequestToken;
import org.keycloak.protocol.aauth.storage.AAuthRequestTokenStore;
import org.keycloak.services.ErrorPageException;
import org.keycloak.services.Urls;
import org.keycloak.services.managers.AuthenticationManager;
import org.keycloak.services.managers.AuthenticationSessionManager;
import org.keycloak.sessions.AuthenticationSessionModel;
import org.keycloak.sessions.RootAuthenticationSessionModel;
import org.keycloak.theme.Theme;
import org.keycloak.theme.beans.AdvancedMessageFormatterMethod;
import org.keycloak.theme.beans.LocaleBean;
import org.keycloak.theme.beans.MessageFormatterMethod;
import org.keycloak.theme.freemarker.FreeMarkerProvider;
import org.keycloak.models.utils.SystemClientUtil;
import org.keycloak.utils.MediaType;
import org.keycloak.util.TokenUtil;

import java.util.Arrays;
import java.util.Collections;
import java.util.HashMap;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Locale;
import java.util.Map;
import java.util.Properties;
import java.util.Set;
import java.util.stream.Collectors;

import jakarta.ws.rs.Consumes;
import jakarta.ws.rs.GET;
import jakarta.ws.rs.Path;
import jakarta.ws.rs.POST;
import jakarta.ws.rs.core.MultivaluedMap;
import jakarta.ws.rs.core.Response;
import jakarta.ws.rs.core.UriBuilder;

import java.net.URI;
import java.util.UUID;

/**
 * Authorization endpoint for AAuth user consent flow.
 *
 * Handles user authentication and consent for AAuth authorization requests.
 * Similar to OIDC AuthorizationEndpoint but for AAuth protocol.
 */
public class AAuthAuthorizationEndpoint {

    private static final Logger logger = Logger.getLogger(AAuthAuthorizationEndpoint.class);

    private static final String REQUEST_TOKEN_PARAM = "request_token";
    private static final String REDIRECT_URI_PARAM = "redirect_uri";
    private static final String STATE_PARAM = "state";
    private static final String CODE_PARAM = "code";
    private static final String ERROR_PARAM = "error";
    private static final String ERROR_DESCRIPTION_PARAM = "error_description";
    private static final String PROMPT_PARAM = "prompt";
    private static final String PROMPT_CONSENT = "consent";

    /** Session note prefix for AAuth consent: key is aauth.consent.{agentId}|{resourceId}, value is comma-separated scopes. */
    private static final String SESSION_NOTE_AAUTH_CONSENT_PREFIX = "aauth.consent.";

    private final KeycloakSession session;
    private final EventBuilder event;
    private final RealmModel realm;
    private final ClientConnection clientConnection;

    public AAuthAuthorizationEndpoint(KeycloakSession session, EventBuilder event) {
        this.session = session;
        this.event = event;
        this.realm = session.getContext().getRealm();
        this.clientConnection = session.getContext().getConnection();
    }

    @GET
    public Response authorizeGet() {
        MultivaluedMap<String, String> params = session.getContext().getUri().getQueryParameters();
        return processAuthorization(params);
    }

    @POST
    @Consumes(jakarta.ws.rs.core.MediaType.APPLICATION_FORM_URLENCODED)
    public Response authorizePost() {
        MultivaluedMap<String, String> params = session.getContext().getHttpRequest().getDecodedFormParameters();
        return processAuthorization(params);
    }

    @Path("consent")
    @POST
    @Consumes(jakarta.ws.rs.core.MediaType.APPLICATION_FORM_URLENCODED)
    public Response processConsent() {
        event.event(EventType.LOGIN);

        checkSsl();
        checkRealm();

        MultivaluedMap<String, String> formData = session.getContext()
                .getHttpRequest().getDecodedFormParameters();

        String consentCode = formData.getFirst("consent_code");
        boolean isAccept = formData.containsKey("accept");

        if (consentCode == null || consentCode.isEmpty()) {
            return createErrorResponse(null, OAuthErrorException.INVALID_REQUEST,
                    "Missing required parameter: consent_code");
        }

        // Retrieve and consume consent data
        Map<String, String> consentData = session.singleUseObjects().remove(consentCode);
        if (consentData == null) {
            return createErrorResponse(null, OAuthErrorException.INVALID_REQUEST,
                    "Invalid or expired consent code");
        }

        String requestTokenId = consentData.get("request_token_id");
        String redirectUri = consentData.get("redirect_uri");
        String state = consentData.get("state");
        String userSessionId = consentData.get("user_session_id");

        if (!isAccept) {
            // User denied - redirect with error
            event.error(org.keycloak.events.Errors.REJECTED_BY_USER);
            return redirectWithError(redirectUri, "access_denied",
                    "User denied the authorization request", state);
        }

        // User accepted - retrieve request token and generate code
        AAuthRequestTokenStore tokenStore = new AAuthRequestTokenStore(session);
        AAuthRequestToken tokenData = tokenStore.getRequestTokenById(requestTokenId);

        if (tokenData == null) {
            return createErrorResponse(redirectUri, OAuthErrorException.INVALID_REQUEST,
                    "Request token expired");
        }

        // Retrieve user session from stored ID
        UserSessionModel userSession = null;
        if (userSessionId != null) {
            userSession = session.sessions().getUserSession(realm, userSessionId);
        }
        if (userSession == null) {
            // Fallback: try to get from SSO cookie
            AuthenticationManager.AuthResult authResult = AuthenticationManager.authenticateIdentityCookie(session, realm, true);
            if (authResult != null) {
                userSession = authResult.getSession();
            }
        }
        if (userSession == null) {
            return createErrorResponse(redirectUri, OAuthErrorException.INVALID_REQUEST,
                    "User session not found or expired");
        }

        // Record consent in session so we can skip the consent screen on subsequent requests this session
        addSessionConsent(userSession, tokenData.getAgentId(), tokenData.getResourceId(), tokenData.getScope());

        String code = generateAuthorizationCode(tokenData, userSession);

        event.event(EventType.CODE_TO_TOKEN);
        event.detail(Details.CONSENT, Details.CONSENT_VALUE_CONSENT_GRANTED);
        event.detail(Details.CODE_ID, code);
        event.success();

        return redirectWithCode(redirectUri, code, state);
    }


    private Response processAuthorization(MultivaluedMap<String, String> params) {
        event.event(EventType.LOGIN);

        checkSsl();
        checkRealm();

        String requestToken = params.getFirst(REQUEST_TOKEN_PARAM);
        String redirectUri = params.getFirst(REDIRECT_URI_PARAM);
        String state = params.getFirst(STATE_PARAM);

        // If request_token not in params, try to get it from authentication session (return from login)
        if (requestToken == null || requestToken.isEmpty()) {
            AuthenticationSessionManager authSessionManager = new AuthenticationSessionManager(session);
            RootAuthenticationSessionModel rootAuthSession = authSessionManager.getCurrentRootAuthenticationSession(realm);
            if (rootAuthSession != null) {
                ClientModel client = SystemClientUtil.getSystemClient(realm);
                // Get authentication session for the client (there should be only one)
                Map<String, AuthenticationSessionModel> authSessions = rootAuthSession.getAuthenticationSessions();
                for (AuthenticationSessionModel authSession : authSessions.values()) {
                    if (client.equals(authSession.getClient())) {
                        requestToken = authSession.getClientNote(REQUEST_TOKEN_PARAM);
                        if (redirectUri == null) {
                            redirectUri = authSession.getClientNote(REDIRECT_URI_PARAM);
                        }
                        if (state == null) {
                            state = authSession.getClientNote(STATE_PARAM);
                        }
                        break;
                    }
                }
            }
        }

        if (requestToken == null || requestToken.isEmpty()) {
            logger.warn("AAuth consent flow: Missing request_token parameter");
            return createErrorResponse(redirectUri, OAuthErrorException.INVALID_REQUEST,
                    "Missing required parameter: request_token");
        }

        logger.infof("AAuth consent flow: Validating request_token (redirect_uri=%s)", redirectUri != null ? "present" : "from token");

        // Validate request token
        AAuthRequestTokenStore tokenStore = new AAuthRequestTokenStore(session);
        AAuthRequestToken tokenData = tokenStore.validateRequestToken(requestToken);

        if (tokenData == null) {
            logger.warn("AAuth consent flow: Invalid or expired request_token");
            return createErrorResponse(redirectUri, OAuthErrorException.INVALID_REQUEST,
                    "Invalid or expired request_token");
        }

        // Use redirect_uri from token if not provided in request
        if (redirectUri == null || redirectUri.isEmpty()) {
            redirectUri = tokenData.getRedirectUri();
        } else if (!redirectUri.equals(tokenData.getRedirectUri())) {
            return createErrorResponse(tokenData.getRedirectUri(), OAuthErrorException.INVALID_REQUEST,
                    "redirect_uri mismatch");
        }

        // Check if user is authenticated by looking up existing session from SSO cookie
        // This finds users already logged in via OIDC or any other protocol
        AuthenticationManager.AuthResult authResult = AuthenticationManager.authenticateIdentityCookie(session, realm, true);

        if (authResult == null || authResult.getSession() == null) {
            // User not authenticated - redirect to login
            logger.infof("AAuth consent flow: User not authenticated (no SSO cookie), redirecting to login (agent=%s)", tokenData.getAgentId());
            return redirectToLogin(requestToken, redirectUri, state);
        }

        UserSessionModel userSession = authResult.getSession();
        UserModel user = authResult.getUser();

        // If user already consented to this agent+resource+scopes this session, skip consent screen (unless prompt=consent)
        String prompt = params.getFirst(PROMPT_PARAM);
        if (!TokenUtil.hasPrompt(prompt, PROMPT_CONSENT)
                && hasSessionConsent(userSession, tokenData.getAgentId(), tokenData.getResourceId(), tokenData.getScope())) {
            event.detail(Details.CONSENT, Details.CONSENT_VALUE_PERSISTED_CONSENT);
            String code = generateAuthorizationCode(tokenData, userSession);
            event.event(EventType.CODE_TO_TOKEN);
            event.detail(Details.CODE_ID, code);
            event.success();
            logger.infof("AAuth consent flow: Skipping consent screen (already consented this session) agent=%s resource=%s user=%s",
                    tokenData.getAgentId(), tokenData.getResourceId(), user.getUsername());
            return redirectWithCode(redirectUri, code, state);
        }

        // User is authenticated - show consent screen
        logger.infof("AAuth consent flow: User authenticated via SSO cookie, showing consent screen (agent=%s, resource=%s, user=%s)",
                tokenData.getAgentId(), tokenData.getResourceId(), user.getUsername());
        return showConsentScreen(tokenData, user, userSession);
    }

    private Response redirectToLogin(String requestToken, String redirectUri, String state) {
        // Create authentication session for login flow
        // Use system client since AAuth doesn't use traditional OIDC clients
        ClientModel client = SystemClientUtil.getSystemClient(realm);

        // Create root authentication session with browser cookie
        AuthenticationSessionManager authSessionManager = new AuthenticationSessionManager(session);
        RootAuthenticationSessionModel rootAuthSession = authSessionManager.createAuthenticationSession(realm, true);

        // Create authentication session for the client
        AuthenticationSessionModel authSession = rootAuthSession.createAuthenticationSession(client);
        authSession.setAction(AuthenticationSessionModel.Action.AUTHENTICATE.name());
        // Use "aauth" protocol so our AAuthLoginProtocol handles the post-authentication redirect
        authSession.setProtocol("aauth");

        // Store request token and redirect URI in authentication session
        URI currentUri = session.getContext().getUri().getRequestUri();
        authSession.setRedirectUri(currentUri.toString());
        authSession.setClientNote(REQUEST_TOKEN_PARAM, requestToken);
        if (redirectUri != null) {
            authSession.setClientNote(REDIRECT_URI_PARAM, redirectUri);
        }
        if (state != null) {
            authSession.setClientNote(STATE_PARAM, state);
        }

        // Build login URL - Keycloak will automatically use the authentication session cookie
        URI loginUrl = Urls.realmLoginPage(session.getContext().getUri().getBaseUri(), realm.getName());

        // Add tab_id parameter to link to the authentication session
        UriBuilder loginUriBuilder = UriBuilder.fromUri(loginUrl);
        loginUriBuilder.queryParam("client_id", client.getClientId());
        loginUriBuilder.queryParam("tab_id", authSession.getTabId());

        return Response.seeOther(loginUriBuilder.build()).build();
    }

    private Response showConsentScreen(AAuthRequestToken tokenData, UserModel user, UserSessionModel userSession) {
        try {
            // 1. Create one-time consent code and store request_token_id + user session id
            String consentCode = UUID.randomUUID().toString();
            Map<String, String> consentData = new HashMap<>();
            consentData.put("request_token_id", tokenData.getId());
            consentData.put("redirect_uri", tokenData.getRedirectUri());
            consentData.put("user_session_id", userSession.getId()); // Store user session for code generation
            if (tokenData.getState() != null) {
                consentData.put("state", tokenData.getState());
            }
            session.singleUseObjects().put(consentCode, 600, consentData); // 10 min TTL

            // 2. Get theme and FreeMarker provider
            Theme theme = session.theme().getTheme(Theme.Type.LOGIN);
            FreeMarkerProvider freeMarker = session.getProvider(FreeMarkerProvider.class);

            // 3. Setup attributes (following KeycloakErrorHandler pattern)
            Locale locale = session.getContext().resolveLocale(user);
            Properties messagesBundle = theme.getEnhancedMessages(realm, locale);
            Map<String, Object> attributes = new HashMap<>();

            attributes.put("realm", new RealmBean(realm));
            attributes.put("url", new UrlBean(realm, theme, session.getContext().getUri().getBaseUri(), null));
            attributes.put("locale", new LocaleBean(realm, locale,
                    session.getContext().getUri().getRequestUriBuilder(), messagesBundle));
            attributes.put("lang", locale.toLanguageTag());
            attributes.put("msg", new MessageFormatterMethod(locale, messagesBundle));
            attributes.put("advancedMsg", new AdvancedMessageFormatterMethod(locale, messagesBundle));
            Properties themeProperties = theme.getProperties();
            attributes.put("properties", themeProperties);
            // darkMode required by keycloak.v2 template.ftl registrationLayout macro
            attributes.put("darkMode", "true".equals(themeProperties.getProperty("darkMode"))
                    && Boolean.TRUE.equals(realm.getAttribute("darkMode", true)));
            // pageId is derived from template name (without .ftl extension)
            attributes.put("pageId", "aauth-grant");

            // 4. Add AAuth-specific bean
            String consentActionUrl = session.getContext().getUri().getBaseUri()
                    + "realms/" + realm.getName() + "/protocol/aauth/agent/auth/consent";
            List<String> scopes = tokenData.getScope() != null && !tokenData.getScope().trim().isEmpty()
                    ? Arrays.asList(tokenData.getScope().split("\\s+"))
                    : Collections.emptyList();

            attributes.put("aauth", new AAuthConsentBean(
                    consentCode, tokenData.getAgentId(), tokenData.getResourceId(),
                    scopes, consentActionUrl));

            // 5. Render template
            logger.infof("AAuth consent flow: Rendering consent template login-aauth-grant.ftl for theme=%s", theme.getName());
            String content = freeMarker.processTemplate(attributes, "login-aauth-grant.ftl", theme);
            return Response.ok(content).type(MediaType.TEXT_HTML_UTF_8_TYPE).build();
        } catch (Throwable t) {
            logger.error("AAuth consent flow: Failed to render consent screen", t);
            return createErrorResponse(tokenData.getRedirectUri(), OAuthErrorException.SERVER_ERROR,
                    "Failed to render consent screen");
        }
    }

    private String generateAuthorizationCode(AAuthRequestToken tokenData, UserSessionModel userSession) {
        String codeId = UUID.randomUUID().toString();
        int codeLifespan = 60; // 60 seconds default

        // Create AAuth authorization code with request token data
        AAuthAuthorizationCode codeData = new AAuthAuthorizationCode(
                codeId,
                Time.currentTime() + codeLifespan,
                tokenData.getScope(),
                tokenData.getRedirectUri(),
                userSession.getId(),
                tokenData.getId(), // request token ID
                tokenData.getAgentId(),
                tokenData.getAgentJkt(),
                tokenData.getSignatureScheme(),
                tokenData.getResourceId()
        );

        // Store code in SingleUseObjectProvider
        session.singleUseObjects().put(codeId, codeLifespan, codeData.serialize());

        // Return opaque code: {codeId}.{userSessionId}.{hash}
        String hash = org.keycloak.common.util.Base64Url.encode((codeId + ":" + userSession.getId()).getBytes(java.nio.charset.StandardCharsets.UTF_8));
        return codeId + "." + userSession.getId() + "." + hash;
    }

    private Response redirectWithCode(String redirectUri, String code, String state) {
        UriBuilder uriBuilder = UriBuilder.fromUri(redirectUri);
        uriBuilder.queryParam(CODE_PARAM, code);
        if (state != null) {
            uriBuilder.queryParam(STATE_PARAM, state);
        }

        return Response.seeOther(uriBuilder.build()).build();
    }

    private Response redirectWithError(String redirectUri, String error, String errorDescription, String state) {
        UriBuilder uriBuilder = UriBuilder.fromUri(redirectUri);
        uriBuilder.queryParam(ERROR_PARAM, error);
        if (errorDescription != null) {
            uriBuilder.queryParam(ERROR_DESCRIPTION_PARAM, errorDescription);
        }
        if (state != null) {
            uriBuilder.queryParam(STATE_PARAM, state);
        }

        return Response.seeOther(uriBuilder.build()).build();
    }

    private Response createErrorResponse(String redirectUri, String error, String errorDescription) {
        if (redirectUri != null) {
            return redirectWithError(redirectUri, error, errorDescription, null);
        }

        // Return JSON error response
        return Response.status(Response.Status.BAD_REQUEST)
                .entity(String.format("{\"error\":\"%s\",\"error_description\":\"%s\"}", error, errorDescription))
                .type(MediaType.APPLICATION_JSON_TYPE)
                .build();
    }

    private String extractRequestTokenId(String requestToken) {
        if (requestToken == null) {
            return null;
        }
        String[] parts = requestToken.split("\\.", 3);
        return parts.length > 0 ? parts[0] : requestToken;
    }

    /**
     * Session note key for AAuth consent: one key per (agentId, resourceId).
     * Value is comma-separated list of consented scope names.
     */
    private static String consentNoteKey(String agentId, String resourceId) {
        return SESSION_NOTE_AAUTH_CONSENT_PREFIX + agentId + "|" + resourceId;
    }

    /**
     * Record that the user has consented to the given agent, resource, and scopes for this session.
     * Merges with any existing consent for the same agent+resource (adds new scopes).
     */
    private void addSessionConsent(UserSessionModel userSession, String agentId, String resourceId, String scopeString) {
        if (agentId == null || resourceId == null) {
            return;
        }
        Set<String> scopes = parseScopes(scopeString);
        if (scopes.isEmpty()) {
            return;
        }
        String key = consentNoteKey(agentId, resourceId);
        String existing = userSession.getNote(key);
        if (existing != null && !existing.isEmpty()) {
            scopes.addAll(Arrays.asList(existing.split(",")));
        }
        userSession.setNote(key, scopes.stream().sorted().collect(Collectors.joining(",")));
        logger.debugf("AAuth session consent: recorded for agent=%s resource=%s scopes=%s", agentId, resourceId, scopes);
    }

    /**
     * Returns true if the user session already has consent for this agent, resource, and at least the requested scopes.
     * Used to skip the consent screen when the user already consented in this session.
     */
    private boolean hasSessionConsent(UserSessionModel userSession, String agentId, String resourceId, String scopeString) {
        if (agentId == null || resourceId == null) {
            return false;
        }
        Set<String> requested = parseScopes(scopeString);
        if (requested.isEmpty()) {
            return true;
        }
        String key = consentNoteKey(agentId, resourceId);
        String value = userSession.getNote(key);
        if (value == null || value.isEmpty()) {
            return false;
        }
        Set<String> consented = new LinkedHashSet<>(Arrays.asList(value.split(",")));
        boolean covered = consented.containsAll(requested);
        if (covered) {
            logger.debugf("AAuth session consent: skipping consent screen (already consented this session) agent=%s resource=%s", agentId, resourceId);
        }
        return covered;
    }

    private static Set<String> parseScopes(String scopeString) {
        if (scopeString == null || scopeString.trim().isEmpty()) {
            return Collections.emptySet();
        }
        return Arrays.stream(scopeString.trim().split("\\s+"))
                .map(String::trim)
                .filter(s -> !s.isEmpty())
                .collect(Collectors.toCollection(LinkedHashSet::new));
    }

    private void checkSsl() {
        if (!session.getContext().getUri().getBaseUri().getScheme().equals("https")
                && realm.getSslRequired().isRequired(clientConnection)) {
            throw new ErrorPageException(session, null, Response.Status.FORBIDDEN,
                    "HTTPS required");
        }
    }

    private void checkRealm() {
        if (!realm.isEnabled()) {
            throw new ErrorPageException(session, null, Response.Status.FORBIDDEN,
                    "Realm not enabled");
        }
    }
}
