<#import "template.ftl" as layout>

<#--
  Theme compatibility: this template only relies on template.ftl and the kc* properties
  that exist in both the keycloak.v2 (PatternFly 5) and the classic keycloak (PatternFly 3/4)
  login themes. It deliberately does not import buttons.ftl, which only exists in keycloak.v2.
-->
<#if properties.kcButtonSecondaryClass??>
    <#assign kcButtonSecondary = properties.kcButtonSecondaryClass>
<#else>
    <#assign kcButtonSecondary = properties.kcButtonDefaultClass!"">
</#if>

<#macro consentForm>
    <form class="${properties.kcFormClass!} ${properties.kcMarginTopClass!}" action="${aauth.consentActionUrl}" method="POST">
        <input type="hidden" name="consent_code" value="${aauth.consentCode}">
        <div class="${properties.kcFormGroupClass!}">
            <div id="kc-form-buttons" class="${properties.kcFormActionGroupClass!}">
                <button class="${properties.kcButtonClass!} ${properties.kcButtonPrimaryClass!} ${properties.kcButtonLargeClass!}"
                        name="accept" id="kc-login" type="submit">${msg("doYes")}</button>
                <button class="${properties.kcButtonClass!} ${kcButtonSecondary} ${properties.kcButtonLargeClass!}"
                        name="cancel" id="kc-cancel" type="submit">${msg("doNo")}</button>
            </div>
        </div>
    </form>
</#macro>

<@layout.registrationLayout bodyClass="oauth"; section>
    <#if section = "header">
        <p>${msg("aauthConsentTitle")}</p>
    <#elseif section = "form">
        <div id="kc-oauth" class="content-area">
            <h3>${msg("aauthConsentRequest")}</h3>
            <p><strong>${msg("aauthConsentAgent")}:</strong> ${aauth.agentId}</p>
            <#if aauth.resourceId?has_content>
                <p><strong>${msg("aauthConsentResource")}:</strong> ${aauth.resourceId}</p>
            </#if>
            <#if aauth.scopes?has_content>
                <h3>${msg("aauthConsentScopes")}</h3>
                <p>${msg("aauthConsentDescription")}</p>
                <ul class="${properties.kcListClass!}">
                    <#list aauth.scopes as scope>
                        <li><span>${scope}</span></li>
                    </#list>
                </ul>
            </#if>

            <#if aauth.clarificationEnabled>
                <hr/>
                <#if aauth.awaitingResponse>
                    <div id="kc-aauth-clarification-waiting">
                        <h4>${msg("aauthClarificationWaiting")}</h4>
                        <p><strong>${msg("aauthClarificationYourQuestion")}:</strong> ${aauth.clarification!}</p>
                        <p><em>${msg("aauthClarificationWaitingHint")}</em></p>
                        <a id="kc-aauth-refresh" class="${properties.kcButtonClass!} ${kcButtonSecondary}"
                           href="${aauth.refreshUrl!}">${msg("aauthClarificationRefresh")}</a>
                    </div>
                <#elseif aauth.clarification?has_content && aauth.clarificationResponse?has_content>
                    <div id="kc-aauth-clarification-answered">
                        <h4>${msg("aauthClarificationTitle")}</h4>
                        <p><strong>${msg("aauthClarificationYourQuestion")}:</strong> ${aauth.clarification}</p>
                        <p><strong>${msg("aauthClarificationAgentResponse")}:</strong> ${aauth.clarificationResponse}</p>
                    </div>
                    <@consentForm/>
                <#else>
                    <div id="kc-aauth-clarification-form">
                        <h4>${msg("aauthClarificationTitle")}</h4>
                        <p>${msg("aauthClarificationPrompt")}</p>
                        <form class="${properties.kcFormClass!}" action="${aauth.clarifyActionUrl}" method="POST">
                            <input type="hidden" name="pending_request_id" value="${aauth.pendingRequestId!}">
                            <input type="hidden" name="interaction_code" value="${aauth.interactionCode!}">
                            <input type="hidden" name="callback_url" value="${aauth.callbackUrl!}">
                            <input type="hidden" name="state" value="${aauth.state!}">
                            <div class="${properties.kcFormGroupClass!}">
                                <#if properties.kcTextareaClass??>
                                    <#-- classic theme: the control class goes on the textarea itself -->
                                    <textarea id="kc-aauth-clarification-question" class="${properties.kcTextareaClass}"
                                              name="clarification_question" rows="3"
                                              placeholder="${msg("aauthClarificationPlaceholder")}"></textarea>
                                <#else>
                                    <#-- keycloak.v2 theme: PatternFly 5 wraps the control in a span -->
                                    <span class="${properties.kcInputClass!}">
                                        <textarea id="kc-aauth-clarification-question" name="clarification_question" rows="3"
                                                  placeholder="${msg("aauthClarificationPlaceholder")}"></textarea>
                                    </span>
                                </#if>
                            </div>
                            <div class="${properties.kcFormGroupClass!}">
                                <div class="${properties.kcFormActionGroupClass!}">
                                    <button id="kc-aauth-clarify-submit"
                                            class="${properties.kcButtonClass!} ${properties.kcButtonPrimaryClass!}"
                                            type="submit">${msg("aauthClarificationSubmit")}</button>
                                </div>
                            </div>
                        </form>
                        <hr/>
                    </div>
                    <@consentForm/>
                </#if>
            <#else>
                <@consentForm/>
            </#if>
        </div>
    </#if>
</@layout.registrationLayout>
