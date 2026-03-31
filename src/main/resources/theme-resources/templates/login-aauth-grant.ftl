<#import "template.ftl" as layout>
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
                <ul>
                    <#list aauth.scopes as scope>
                        <li>${scope}</li>
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
                        <a class="${properties.kcButtonClass!} ${properties.kcButtonDefaultClass!}"
                           href="${aauth.refreshUrl!}">
                            ${msg("aauthClarificationRefresh")}
                        </a>
                    </div>
                <#elseif aauth.clarification?has_content && aauth.clarificationResponse?has_content>
                    <div id="kc-aauth-clarification-answered">
                        <h4>${msg("aauthClarificationTitle")}</h4>
                        <p><strong>${msg("aauthClarificationYourQuestion")}:</strong> ${aauth.clarification}</p>
                        <p><strong>${msg("aauthClarificationAgentResponse")}:</strong> ${aauth.clarificationResponse}</p>
                    </div>
                    <form class="${properties.kcFormClass!} ${properties.kcMarginTopClass!}" action="${aauth.consentActionUrl}" method="POST">
                        <input type="hidden" name="consent_code" value="${aauth.consentCode}">
                        <div id="kc-form-buttons">
                            <div class="${properties.kcFormButtonsWrapperClass!}">
                                <input class="${properties.kcButtonClass!} ${properties.kcButtonPrimaryClass!} ${properties.kcButtonLargeClass!}" name="accept" id="kc-login" type="submit" value="${msg("doYes")}"/>
                                <input class="${properties.kcButtonClass!} ${properties.kcButtonDefaultClass!} ${properties.kcButtonLargeClass!}" name="cancel" id="kc-cancel" type="submit" value="${msg("doNo")}"/>
                            </div>
                        </div>
                    </form>
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
                                <textarea class="${properties.kcInputClass!}" name="clarification_question" rows="3" placeholder="${msg("aauthClarificationPlaceholder")}"></textarea>
                            </div>
                            <div id="kc-form-buttons">
                                <button class="${properties.kcButtonClass!} ${properties.kcButtonPrimaryClass!}" type="submit">${msg("aauthClarificationSubmit")}</button>
                            </div>
                        </form>
                        <hr/>
                    </div>
                    <form class="${properties.kcFormClass!} ${properties.kcMarginTopClass!}" action="${aauth.consentActionUrl}" method="POST">
                        <input type="hidden" name="consent_code" value="${aauth.consentCode}">
                        <div id="kc-form-buttons">
                            <div class="${properties.kcFormButtonsWrapperClass!}">
                                <input class="${properties.kcButtonClass!} ${properties.kcButtonPrimaryClass!} ${properties.kcButtonLargeClass!}" name="accept" id="kc-login" type="submit" value="${msg("doYes")}"/>
                                <input class="${properties.kcButtonClass!} ${properties.kcButtonDefaultClass!} ${properties.kcButtonLargeClass!}" name="cancel" id="kc-cancel" type="submit" value="${msg("doNo")}"/>
                            </div>
                        </div>
                    </form>
                </#if>
            <#else>
                <form class="${properties.kcFormClass!} ${properties.kcMarginTopClass!}" action="${aauth.consentActionUrl}" method="POST">
                    <input type="hidden" name="consent_code" value="${aauth.consentCode}">
                    <div class="${properties.kcFormGroupClass!}">
                        <div id="kc-form-options">
                            <div class="${properties.kcFormOptionsWrapperClass!}">
                            </div>
                        </div>

                        <div id="kc-form-buttons">
                            <div class="${properties.kcFormButtonsWrapperClass!}">
                                <input class="${properties.kcButtonClass!} ${properties.kcButtonPrimaryClass!} ${properties.kcButtonLargeClass!}" name="accept" id="kc-login" type="submit" value="${msg("doYes")}"/>
                                <input class="${properties.kcButtonClass!} ${properties.kcButtonDefaultClass!} ${properties.kcButtonLargeClass!}" name="cancel" id="kc-cancel" type="submit" value="${msg("doNo")}"/>
                            </div>
                        </div>
                    </div>
                </form>
            </#if>

            <div class="clearfix"></div>
        </div>
    </#if>
</@layout.registrationLayout>
