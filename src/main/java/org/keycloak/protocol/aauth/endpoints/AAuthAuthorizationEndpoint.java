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
import org.keycloak.protocol.aauth.AAuthTokenManager;
import org.keycloak.protocol.aauth.forms.AAuthConsentBean;
import org.keycloak.protocol.aauth.storage.AAuthPendingRequest;
import org.keycloak.protocol.aauth.storage.AAuthPendingRequestStore;
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
import org.keycloak.util.TokenUtil;
import org.keycloak.utils.MediaType;

import java.util.Arrays;
import java.util.Collections;
import java.util.HashMap;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Locale;
import java.util.Map;
import java.util.Properties;
import java.util.Set;
import java.util.UUID;
import java.util.stream.Collectors;

import jakarta.ws.rs.Consumes;
import jakarta.ws.rs.GET;
import jakarta.ws.rs.Path;
import jakarta.ws.rs.POST;
import jakarta.ws.rs.core.MultivaluedMap;
import jakarta.ws.rs.core.Response;
import jakarta.ws.rs.core.UriBuilder;

import java.net.URI;

/**
 * Interaction endpoint for AAuth user consent flow.
 *
 * Updated per AAuth spec: accepts an interaction code (not a request_token).
 * After user consent, the pending request is completed (auth token stored in
 * the pending store) and the user is redirected to the callback URL.
 * The agent retrieves the auth token by polling GET /pending/{id}.
 *
 * Paths:
 *   GET  /interact?code=ABCD1234[&callback=https://...]  (primary)
 *   GET  /agent/auth?code=ABCD1234[&callback=https://...]  (legacy alias)
 *   POST /interact/consent                               (consent form submission)
 *   POST /agent/auth/consent                             (legacy alias)
 */
public class AAuthAuthorizationEndpoint {

    private static final Logger logger = Logger.getLogger(AAuthAuthorizationEndpoint.class);

    private static final String INTERACTION_CODE_PARAM = "code";
    private static final String CALLBACK_PARAM = "callback";
    private static final String STATE_PARAM = "state";
    private static final String PROMPT_PARAM = "prompt";
    private static final String PROMPT_CONSENT = "consent";

    // Legacy param names (kept for the AAuthLoginProtocol redirect path)
    private static final String PENDING_ID_PARAM = "pending_id";

    /** Session note prefix for AAuth consent: key is aauth.consent.{agentId}|{resourceId} */
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
        return processInteraction(params);
    }

    @POST
    @Consumes(jakarta.ws.rs.core.MediaType.APPLICATION_FORM_URLENCODED)
    public Response authorizePost() {
        MultivaluedMap<String, String> params = session.getContext().getHttpRequest().getDecodedFormParameters();
        return processInteraction(params);
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

        String pendingRequestId = consentData.get("pending_request_id");
        String callbackUrl = consentData.get("callback_url");
        String state = consentData.get("state");
        String userSessionId = consentData.get("user_session_id");

        if (!isAccept) {
            // User denied
            event.error(org.keycloak.events.Errors.REJECTED_BY_USER);
            AAuthPendingRequestStore pendingStore = new AAuthPendingRequestStore(session);
            pendingStore.denyPendingRequest(pendingRequestId, "access_denied",
                    "User denied the authorization request");
            return showDeniedPage(callbackUrl);
        }

        // Retrieve pending request
        AAuthPendingRequestStore pendingStore = new AAuthPendingRequestStore(session);
        AAuthPendingRequest pending = pendingStore.getPendingRequest(pendingRequestId);

        if (pending == null) {
            return createErrorResponse(null, OAuthErrorException.INVALID_REQUEST,
                    "Pending request expired or not found");
        }

        // Retrieve user session
        UserSessionModel userSession = null;
        if (userSessionId != null) {
            userSession = session.sessions().getUserSession(realm, userSessionId);
        }
        if (userSession == null) {
            AuthenticationManager.AuthResult authResult =
                    AuthenticationManager.authenticateIdentityCookie(session, realm, true);
            if (authResult != null) {
                userSession = authResult.getSession();
            }
        }
        if (userSession == null) {
            return createErrorResponse(null, OAuthErrorException.INVALID_REQUEST,
                    "User session not found or expired");
        }

        UserModel user = userSession.getUser();

        // Record consent in session
        addSessionConsent(userSession, pending.getAgentId(), pending.getResourceId(), pending.getScope());

        // Build the auth token and complete the pending request
        try {
            java.security.PublicKey agentPublicKey = resolveAgentPublicKey(pending.getAgentJkt());
            if (agentPublicKey == null) {
                return createErrorResponse(null, OAuthErrorException.SERVER_ERROR,
                        "Cannot resolve agent public key");
            }

            AAuthTokenManager tokenManager = new AAuthTokenManager(session);
            String authToken = tokenManager.createAuthToken(realm, pending.getAgentId(), null,
                    agentPublicKey, pending.getResourceId(), pending.getScope(), user);

            long expiresIn = tokenManager.getTokenExpiration(realm);
            pendingStore.completePendingRequest(pendingRequestId, authToken, expiresIn);

            event.event(EventType.LOGIN);
            event.detail(Details.CONSENT, Details.CONSENT_VALUE_CONSENT_GRANTED);
            event.success();

            logger.infof("AAuth consent granted: pending=%s agent=%s user=%s",
                    pendingRequestId, pending.getAgentId(), user.getUsername());
        } catch (Exception e) {
            logger.errorf(e, "Failed to create auth token after consent");
            pendingStore.denyPendingRequest(pendingRequestId, "server_error",
                    "Failed to create auth token");
            return createErrorResponse(null, OAuthErrorException.SERVER_ERROR,
                    "Failed to create auth token");
        }

        // Redirect to callback (no token/code in redirect — agent polls pending URL)
        return redirectToCallback(callbackUrl, state);
    }

    /**
     * User submits a clarification question to forward to the agent.
     * Form params: pending_request_id, interaction_code, clarification_question, callback_url, state
     */
    @Path("clarify")
    @POST
    @Consumes(jakarta.ws.rs.core.MediaType.APPLICATION_FORM_URLENCODED)
    public Response processClarify() {
        checkSsl();
        checkRealm();

        MultivaluedMap<String, String> formData = session.getContext()
                .getHttpRequest().getDecodedFormParameters();

        String pendingRequestId = formData.getFirst("pending_request_id");
        String interactionCode = formData.getFirst("interaction_code");
        String question = formData.getFirst("clarification_question");
        String callbackUrl = formData.getFirst("callback_url");
        String state = formData.getFirst("state");

        if (pendingRequestId == null || pendingRequestId.isEmpty()) {
            return showErrorPage("Missing required parameter: pending_request_id");
        }
        if (question == null || question.trim().isEmpty()) {
            return showErrorPage("Clarification question cannot be empty");
        }

        // Verify user is authenticated
        AuthenticationManager.AuthResult authResult =
                AuthenticationManager.authenticateIdentityCookie(session, realm, true);
        if (authResult == null || authResult.getSession() == null) {
            return showErrorPage("User session not found. Please log in again.");
        }

        AAuthPendingRequestStore pendingStore = new AAuthPendingRequestStore(session);
        AAuthPendingRequest pending = pendingStore.getPendingRequest(pendingRequestId);
        if (pending == null) {
            return showErrorPage("Pending request not found or expired");
        }
        if (!pending.isClarificationEnabled()) {
            return showErrorPage("Clarification is not enabled for this request");
        }

        pendingStore.setClarificationQuestion(pendingRequestId, question.trim());

        logger.infof("AAuth clarify: stored question for pending=%s, agent=%s", pendingRequestId, pending.getAgentId());

        // Redirect back to interact page to show "waiting" state
        try {
            UriBuilder uriBuilder = UriBuilder.fromUri(
                    session.getContext().getUri().getBaseUri())
                    .path("realms").path(realm.getName()).path("protocol/aauth/interact");
            if (interactionCode != null && !interactionCode.isEmpty()) {
                uriBuilder.queryParam("code", interactionCode);
            }
            if (callbackUrl != null && !callbackUrl.isEmpty()) {
                uriBuilder.queryParam("callback", callbackUrl);
            }
            if (state != null && !state.isEmpty()) {
                uriBuilder.queryParam("state", state);
            }
            return Response.seeOther(uriBuilder.build()).build();
        } catch (Exception e) {
            logger.warnf(e, "Failed to build redirect URI after clarify");
            return showErrorPage("Failed to redirect after clarification submission");
        }
    }

    private Response processInteraction(MultivaluedMap<String, String> params) {
        event.event(EventType.LOGIN);

        checkSsl();
        checkRealm();

        String interactionCode = params.getFirst(INTERACTION_CODE_PARAM);
        String callbackUrl = params.getFirst(CALLBACK_PARAM);
        String state = params.getFirst(STATE_PARAM);

        // Support legacy pending_id param (from AAuthLoginProtocol redirect)
        String pendingId = params.getFirst(PENDING_ID_PARAM);

        // Try to get from authentication session if returning from login
        if (interactionCode == null && pendingId == null) {
            AuthenticationSessionManager authSessionManager = new AuthenticationSessionManager(session);
            RootAuthenticationSessionModel rootAuthSession =
                    authSessionManager.getCurrentRootAuthenticationSession(realm);
            if (rootAuthSession != null) {
                ClientModel client = SystemClientUtil.getSystemClient(realm);
                Map<String, AuthenticationSessionModel> authSessions = rootAuthSession.getAuthenticationSessions();
                for (AuthenticationSessionModel authSession : authSessions.values()) {
                    if (client.equals(authSession.getClient())) {
                        interactionCode = authSession.getClientNote(INTERACTION_CODE_PARAM);
                        pendingId = authSession.getClientNote(PENDING_ID_PARAM);
                        if (callbackUrl == null) {
                            callbackUrl = authSession.getClientNote(CALLBACK_PARAM);
                        }
                        if (state == null) {
                            state = authSession.getClientNote(STATE_PARAM);
                        }
                        break;
                    }
                }
            }
        }

        // Resolve the pending request
        AAuthPendingRequestStore pendingStore = new AAuthPendingRequestStore(session);
        AAuthPendingRequest pending = null;

        if (interactionCode != null && !interactionCode.isEmpty()) {
            pending = pendingStore.getByInteractionCode(interactionCode);
            if (pending == null) {
                logger.warn("AAuth interaction: invalid or expired interaction code: " + interactionCode);
                return showErrorPage("Invalid or expired interaction code");
            }
        } else if (pendingId != null && !pendingId.isEmpty()) {
            pending = pendingStore.getPendingRequest(pendingId);
            if (pending == null) {
                logger.warn("AAuth interaction: pending request not found: " + pendingId);
                return showErrorPage("Pending request not found or expired");
            }
            interactionCode = pending.getInteractionCode();
        } else {
            logger.warn("AAuth interaction: missing code parameter");
            return showErrorPage("Missing required parameter: code");
        }

        if (callbackUrl == null) {
            callbackUrl = pending.getCallbackUrl();
        }

        // Check if user is authenticated via SSO cookie
        AuthenticationManager.AuthResult authResult =
                AuthenticationManager.authenticateIdentityCookie(session, realm, true);

        if (authResult == null || authResult.getSession() == null) {
            logger.infof("AAuth interaction: user not authenticated, redirecting to login (code=%s)", interactionCode);
            return redirectToLogin(interactionCode, pending.getId(), callbackUrl, state);
        }

        UserSessionModel userSession = authResult.getSession();
        UserModel user = authResult.getUser();

        // Skip consent screen if user already consented this session (unless prompt=consent)
        // Never skip for clarification-enabled requests — they always require deliberate interaction
        String prompt = params.getFirst(PROMPT_PARAM);
        if (!pending.isClarificationEnabled()
                && !TokenUtil.hasPrompt(prompt, PROMPT_CONSENT)
                && hasSessionConsent(userSession, pending.getAgentId(), pending.getResourceId(), pending.getScope())) {
            event.detail(Details.CONSENT, Details.CONSENT_VALUE_PERSISTED_CONSENT);
            return completeConsentAndRedirect(pending, userSession, user, callbackUrl, state, pendingStore);
        }

        // Show consent screen
        logger.infof("AAuth interaction: showing consent screen for agent=%s, resource=%s, user=%s",
                pending.getAgentId(), pending.getResourceId(), user.getUsername());
        return showConsentScreen(pending, user, userSession, callbackUrl, state);
    }

    private Response completeConsentAndRedirect(AAuthPendingRequest pending, UserSessionModel userSession,
            UserModel user, String callbackUrl, String state, AAuthPendingRequestStore pendingStore) {
        try {
            java.security.PublicKey agentPublicKey = resolveAgentPublicKey(pending.getAgentJkt());
            if (agentPublicKey == null) {
                return showErrorPage("Cannot resolve agent public key");
            }

            addSessionConsent(userSession, pending.getAgentId(), pending.getResourceId(), pending.getScope());

            AAuthTokenManager tokenManager = new AAuthTokenManager(session);
            String authToken = tokenManager.createAuthToken(realm, pending.getAgentId(), null,
                    agentPublicKey, pending.getResourceId(), pending.getScope(), user);

            long expiresIn = tokenManager.getTokenExpiration(realm);
            pendingStore.completePendingRequest(pending.getId(), authToken, expiresIn);

            logger.infof("AAuth: auto-completed consent for agent=%s user=%s (session consent)",
                    pending.getAgentId(), user.getUsername());

            return redirectToCallback(callbackUrl, state);
        } catch (Exception e) {
            logger.errorf(e, "Failed to auto-complete consent");
            return showErrorPage("Failed to complete authorization");
        }
    }

    /**
     * Resolve agent's public key from JKT. We stored it in the pending request's agentJkt,
     * but we need the actual public key to create the auth token.
     * Since we don't persist public keys, we attempt to get it from the current session.
     * If the request is coming from the user's browser (not agent), it won't have the key,
     * so we fall back to building a placeholder-free token using the stored JKT approach.
     *
     * Note: In the interaction flow, the user's browser hits this endpoint without signing.
     * The public key needs to come from the pending request's stored state. Since we only
     * stored the JKT (thumbprint), not the full key, we need to store the serialized key too.
     *
     * Workaround: Store the serialized public key JWK in the pending request at creation time.
     */
    private java.security.PublicKey resolveAgentPublicKey(String agentJkt) {
        // The agent public key is stored in the pending request's stored data
        // We need to look it up from the store using the JKT as index.
        // For now, check if it's in the current session (agent signed the token endpoint request)
        java.security.PublicKey key = (java.security.PublicKey) session.getAttribute("aauth.agent.public.key");
        if (key != null) return key;

        // Key not available in session (browser request, not agent request).
        // Retrieve from pending request store by JKT.
        if (agentJkt == null) return null;

        // We need to look up the stored public key JWK from the pending request.
        // The AAuthPendingRequestStore and AAuthPendingRequest store only the JKT.
        // We need to also store the serialized JWK. This is handled by storing
        // "agent_public_key_jwk" in the pending request when it is created.
        // For compatibility, check the store for the key JWK.
        Map<String, String> keyData = session.singleUseObjects().get("aauth.agentkey." + agentJkt);
        if (keyData != null) {
            String jwkJson = keyData.get("jwk");
            if (jwkJson != null) {
                try {
                    org.keycloak.jose.jwk.JWK jwk = org.keycloak.util.JsonSerialization.readValue(jwkJson, org.keycloak.jose.jwk.JWK.class);
                    return org.keycloak.jose.jwk.JWKParser.create(jwk).toPublicKey();
                } catch (Exception e) {
                    logger.warnf(e, "Failed to deserialize agent public key JWK");
                }
            }
        }

        return null;
    }

    private Response redirectToLogin(String interactionCode, String pendingId, String callbackUrl, String state) {
        ClientModel client = SystemClientUtil.getSystemClient(realm);

        AuthenticationSessionManager authSessionManager = new AuthenticationSessionManager(session);
        RootAuthenticationSessionModel rootAuthSession =
                authSessionManager.createAuthenticationSession(realm, true);

        AuthenticationSessionModel authSession = rootAuthSession.createAuthenticationSession(client);
        authSession.setAction(AuthenticationSessionModel.Action.AUTHENTICATE.name());
        authSession.setProtocol("aauth");

        URI currentUri = session.getContext().getUri().getRequestUri();
        authSession.setRedirectUri(currentUri.toString());
        if (interactionCode != null) {
            authSession.setClientNote(INTERACTION_CODE_PARAM, interactionCode);
        }
        if (pendingId != null) {
            authSession.setClientNote(PENDING_ID_PARAM, pendingId);
        }
        if (callbackUrl != null) {
            authSession.setClientNote(CALLBACK_PARAM, callbackUrl);
        }
        if (state != null) {
            authSession.setClientNote(STATE_PARAM, state);
        }

        URI loginUrl = Urls.realmLoginPage(session.getContext().getUri().getBaseUri(), realm.getName());
        UriBuilder loginUriBuilder = UriBuilder.fromUri(loginUrl);
        loginUriBuilder.queryParam("client_id", client.getClientId());
        loginUriBuilder.queryParam("tab_id", authSession.getTabId());

        return Response.seeOther(loginUriBuilder.build()).build();
    }

    private Response showConsentScreen(AAuthPendingRequest pending, UserModel user,
            UserSessionModel userSession, String callbackUrl, String state) {
        try {
            // Create one-time consent code
            String consentCode = UUID.randomUUID().toString();
            Map<String, String> consentData = new HashMap<>();
            consentData.put("pending_request_id", pending.getId());
            consentData.put("callback_url", callbackUrl != null ? callbackUrl : "");
            consentData.put("user_session_id", userSession.getId());
            if (state != null) {
                consentData.put("state", state);
            }
            session.singleUseObjects().put(consentCode, 600, consentData);

            Theme theme = session.theme().getTheme(Theme.Type.LOGIN);
            FreeMarkerProvider freeMarker = session.getProvider(FreeMarkerProvider.class);

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
            attributes.put("darkMode", "true".equals(themeProperties.getProperty("darkMode"))
                    && Boolean.TRUE.equals(realm.getAttribute("darkMode", true)));
            attributes.put("pageId", "aauth-grant");

            String baseUri = session.getContext().getUri().getBaseUri().toString();
            String consentActionUrl = baseUri + "realms/" + realm.getName() + "/protocol/aauth/interact/consent";
            String clarifyActionUrl = baseUri + "realms/" + realm.getName() + "/protocol/aauth/interact/clarify";
            List<String> scopes = pending.getScope() != null && !pending.getScope().trim().isEmpty()
                    ? Arrays.asList(pending.getScope().split("\\s+"))
                    : Collections.emptyList();

            AAuthConsentBean consentBean = new AAuthConsentBean(
                    consentCode, pending.getAgentId(), pending.getResourceId(),
                    scopes, consentActionUrl);
            consentBean.setClarificationEnabled(pending.isClarificationEnabled());
            consentBean.setClarification(pending.getClarification());
            consentBean.setClarificationResponse(pending.getClarificationResponse());
            consentBean.setPendingRequestId(pending.getId());
            consentBean.setInteractionCode(pending.getInteractionCode());
            consentBean.setCallbackUrl(callbackUrl != null ? callbackUrl : "");
            consentBean.setState(state != null ? state : "");
            consentBean.setClarifyActionUrl(clarifyActionUrl);

            // Build a refresh URL so the "waiting" state can reload the consent screen
            UriBuilder refreshUriBuilder = UriBuilder.fromUri(session.getContext().getUri().getBaseUri())
                    .path("realms").path(realm.getName()).path("protocol/aauth/interact");
            if (pending.getInteractionCode() != null) {
                refreshUriBuilder.queryParam("code", pending.getInteractionCode());
            }
            if (callbackUrl != null && !callbackUrl.isEmpty()) {
                refreshUriBuilder.queryParam("callback", callbackUrl);
            }
            if (state != null && !state.isEmpty()) {
                refreshUriBuilder.queryParam("state", state);
            }
            consentBean.setRefreshUrl(refreshUriBuilder.build().toString());
            attributes.put("aauth", consentBean);

            logger.infof("AAuth interaction: rendering consent screen for theme=%s", theme.getName());
            String content = freeMarker.processTemplate(attributes, "login-aauth-grant.ftl", theme);
            return Response.ok(content).type(MediaType.TEXT_HTML_UTF_8_TYPE).build();
        } catch (Throwable t) {
            logger.error("AAuth interaction: failed to render consent screen", t);
            return showErrorPage("Failed to render consent screen");
        }
    }

    private Response redirectToCallback(String callbackUrl, String state) {
        if (callbackUrl == null || callbackUrl.isEmpty()) {
            return showCompletionPage();
        }
        try {
            UriBuilder uriBuilder = UriBuilder.fromUri(callbackUrl);
            if (state != null) {
                uriBuilder.queryParam(STATE_PARAM, state);
            }
            return Response.seeOther(uriBuilder.build()).build();
        } catch (Exception e) {
            logger.warnf(e, "Invalid callback URL: %s", callbackUrl);
            return showCompletionPage();
        }
    }

    private Response showCompletionPage() {
        return Response.ok(
                "<html><body><h2>Authorization Complete</h2>"
                + "<p>You may close this window. The agent has been authorized.</p></body></html>")
                .type(MediaType.TEXT_HTML_UTF_8_TYPE)
                .build();
    }

    private Response showDeniedPage(String callbackUrl) {
        if (callbackUrl != null && !callbackUrl.isEmpty()) {
            try {
                URI uri = UriBuilder.fromUri(callbackUrl)
                        .queryParam("error", "access_denied").build();
                return Response.seeOther(uri).build();
            } catch (Exception ignore) {}
        }
        return Response.ok(
                "<html><body><h2>Authorization Denied</h2>"
                + "<p>You denied the authorization request.</p></body></html>")
                .type(MediaType.TEXT_HTML_UTF_8_TYPE)
                .build();
    }

    private Response showErrorPage(String message) {
        return Response.status(Response.Status.BAD_REQUEST)
                .entity("<html><body><h2>Error</h2><p>" + escapeHtml(message) + "</p></body></html>")
                .type(MediaType.TEXT_HTML_UTF_8_TYPE)
                .build();
    }

    private static String escapeHtml(String s) {
        if (s == null) return "";
        return s.replace("&", "&amp;").replace("<", "&lt;").replace(">", "&gt;");
    }

    private Response createErrorResponse(String redirectUrl, String error, String errorDescription) {
        return Response.status(Response.Status.BAD_REQUEST)
                .entity(String.format("{\"error\":\"%s\",\"error_description\":\"%s\"}",
                        error, errorDescription))
                .type(jakarta.ws.rs.core.MediaType.APPLICATION_JSON)
                .build();
    }

    private static String consentNoteKey(String agentId, String resourceId) {
        return SESSION_NOTE_AAUTH_CONSENT_PREFIX + agentId + "|" + resourceId;
    }

    private void addSessionConsent(UserSessionModel userSession, String agentId,
            String resourceId, String scopeString) {
        if (agentId == null || resourceId == null) return;
        Set<String> scopes = parseScopes(scopeString);
        if (scopes.isEmpty()) return;
        String key = consentNoteKey(agentId, resourceId);
        String existing = userSession.getNote(key);
        if (existing != null && !existing.isEmpty()) {
            scopes.addAll(Arrays.asList(existing.split(",")));
        }
        userSession.setNote(key, scopes.stream().sorted().collect(Collectors.joining(",")));
    }

    private boolean hasSessionConsent(UserSessionModel userSession, String agentId,
            String resourceId, String scopeString) {
        if (agentId == null || resourceId == null) return false;
        Set<String> requested = parseScopes(scopeString);
        if (requested.isEmpty()) return true;
        String key = consentNoteKey(agentId, resourceId);
        String value = userSession.getNote(key);
        if (value == null || value.isEmpty()) return false;
        Set<String> consented = new LinkedHashSet<>(Arrays.asList(value.split(",")));
        return consented.containsAll(requested);
    }

    private static Set<String> parseScopes(String scopeString) {
        if (scopeString == null || scopeString.trim().isEmpty()) return Collections.emptySet();
        return Arrays.stream(scopeString.trim().split("\\s+"))
                .map(String::trim)
                .filter(s -> !s.isEmpty())
                .collect(Collectors.toCollection(LinkedHashSet::new));
    }

    private void checkSsl() {
        if (!session.getContext().getUri().getBaseUri().getScheme().equals("https")
                && realm.getSslRequired().isRequired(clientConnection)) {
            throw new ErrorPageException(session, null, Response.Status.FORBIDDEN, "HTTPS required");
        }
    }

    private void checkRealm() {
        if (!realm.isEnabled()) {
            throw new ErrorPageException(session, null, Response.Status.FORBIDDEN, "Realm not enabled");
        }
    }
}
