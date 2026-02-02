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
            <div class="clearfix"></div>
        </div>
    </#if>
</@layout.registrationLayout>
