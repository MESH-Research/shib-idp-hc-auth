/*
* Copyright (C) 2017 Modern Language Association
*
* Licensed under the Apache License, Version 2.0 (the "License"); you may not use this file
* except in compliance with the License. You may obtain a copy of the License at
*
* http://www.apache.org/licenses/LICENSE-2.0
* 
* Unless required by applicable law or agreed to in writing, software distributed under
* the License is distributed on an "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
* KIND, either express or implied. See the License for the specific language governing
* permissions and limitations under the License.
*/
package org.mla.cbox.shibboleth.idp.authn.impl;

import javax.annotation.Nonnull;
import javax.servlet.http.HttpServletRequest;

import net.shibboleth.idp.authn.AbstractExtractionAction;
import net.shibboleth.idp.authn.AuthnEventIds;
import net.shibboleth.idp.authn.context.AuthenticationContext;
import net.shibboleth.idp.authn.context.AuthenticationErrorContext;
import net.shibboleth.idp.authn.context.LDAPResponseContext;
import net.shibboleth.idp.authn.context.UsernamePasswordContext;
import net.shibboleth.utilities.java.support.annotation.constraint.NonnullAfterInit;
import net.shibboleth.utilities.java.support.annotation.constraint.NotEmpty;
import net.shibboleth.utilities.java.support.component.ComponentSupport;
import net.shibboleth.utilities.java.support.logic.Constraint;
import net.shibboleth.utilities.java.support.primitive.StringSupport;

import org.ldaptive.auth.AuthenticationResponse;
import org.ldaptive.AttributeModification;
import org.ldaptive.AttributeModificationType;
import org.ldaptive.ConnectionFactory;
import org.ldaptive.Connection;
import org.ldaptive.LdapAttribute;
import org.ldaptive.LdapEntry;
import org.ldaptive.LdapException;
import org.ldaptive.ModifyOperation;
import org.ldaptive.ModifyRequest;

import org.opensaml.profile.action.ActionSupport;
import org.opensaml.profile.context.ProfileRequestContext;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

/**
 * An action that extracts a password and confirmation password from an HTTP form body or query string,
 * and resets the password in the HC IdP LDAP directory.
 * 
 */
public class ExtractPasswordReset extends AbstractExtractionAction {

    /** Class logger. */
    @Nonnull private final Logger log = LoggerFactory.getLogger(ExtractPasswordReset.class);

    /** LDAP connection factory. */
    @Nonnull private ConnectionFactory connectionFactory;

    /**
     * Returns the connection factory.
     *
     */
    @NonnullAfterInit public ConnectionFactory getConnectionFactory() {
        return connectionFactory;
    }

    /**
     * Sets the connection factory.
     */
    public void setConnectionFactory(@Nonnull final ConnectionFactory factory) {
        connectionFactory = Constraint.isNotNull(factory, "ConnectionFactory cannot be null");
    }

    @Override
    protected void doExecute(@Nonnull final ProfileRequestContext profileRequestContext,
            @Nonnull final AuthenticationContext authenticationContext) {

        log.debug("{} Extracting password for reset...");

        // Grab the authentication error context to report any errors
        // and clear any existing errors.
        AuthenticationErrorContext authErrorContext  = authenticationContext.getSubcontext(AuthenticationErrorContext.class, true);
        authErrorContext.getClassifiedErrors().clear();

        // Grab the current username and password just used for authentication.
        UsernamePasswordContext upContext = authenticationContext.getSubcontext(UsernamePasswordContext.class);
        String userName = upContext.getUsername();
        String currentPassword = upContext.getPassword();

        if (userName == null || userName.isEmpty()) {
            log.error("{} Could not determine username before reset");
            authErrorContext.getClassifiedErrors().add("Error reading username");
            ActionSupport.buildEvent(profileRequestContext, AuthnEventIds.NO_CREDENTIALS);
            return;
        }

        log.info("{} Resetting password for user {}", getLogPrefix(), userName);

        if (currentPassword == null || currentPassword.isEmpty()) {
            log.error("{} Could not determine current password before reset");
            authErrorContext.getClassifiedErrors().add("Error reading current password");
            ActionSupport.buildEvent(profileRequestContext, AuthnEventIds.NO_CREDENTIALS);
            return;
        }

        final HttpServletRequest request = getHttpServletRequest();

        if (request == null) {
            log.error("{} Profile action does not contain an HttpServletRequest", getLogPrefix());
            ActionSupport.buildEvent(profileRequestContext, AuthnEventIds.NO_CREDENTIALS);
            return;
        }
        
        final String newPassword = request.getParameter("j_password");
        final String newPasswordConfirm = request.getParameter("j_password_confirm");

        if (newPassword == null || newPassword.isEmpty()) {
            log.info("{} No password in request", getLogPrefix());
            authErrorContext.getClassifiedErrors().add("Password cannot be empty");
            ActionSupport.buildEvent(profileRequestContext, AuthnEventIds.NO_CREDENTIALS);
            return;
        }

        if (newPassword.equals(currentPassword)) {
            log.info("{} Rejecting new password since it is the same as current password", getLogPrefix());
            authErrorContext.getClassifiedErrors().add("Cannot reuse the existing password");
            ActionSupport.buildEvent(profileRequestContext, AuthnEventIds.NO_CREDENTIALS);
            return;
        }

        if (!newPassword.equals(newPasswordConfirm)) {
            log.info("{} Password and password confirmation do not match", getLogPrefix());
            authErrorContext.getClassifiedErrors().add("Password and password confirmation do not match");
            ActionSupport.buildEvent(profileRequestContext, AuthnEventIds.NO_CREDENTIALS);
            return;
        }

        if (newPassword.length() < 10) {
            log.info("{} Rejecting new password since it is not at least 10 characters long", getLogPrefix());
            authErrorContext.getClassifiedErrors().add("Password must be at least 10 characters long");
            ActionSupport.buildEvent(profileRequestContext, AuthnEventIds.NO_CREDENTIALS);
            return;
        }

        boolean foundDigit = false;
        boolean foundUpper = false;
        boolean foundLower = false;

        char c = 0;

        for (int i = 0; i < newPassword.length(); i++) {
            c = newPassword.charAt(i);
            if (Character.isDigit(c)) {
                foundDigit = true;
            } else if (Character.isLowerCase(c)) {
                foundLower = true;
            } else if (Character.isUpperCase(c)) {
                foundUpper = true;
            }
        }

        if (! foundDigit) {
            log.info("{} Rejecting new password since it does not contain a digit", getLogPrefix());
            authErrorContext.getClassifiedErrors().add("Password must contain a digit");
            ActionSupport.buildEvent(profileRequestContext, AuthnEventIds.NO_CREDENTIALS);
            return;
        }

        if (! foundUpper) {
            log.info("{} Rejecting new password since it does not contain an upper case letter", getLogPrefix());
            authErrorContext.getClassifiedErrors().add("Password must contain an upper case letter");
            ActionSupport.buildEvent(profileRequestContext, AuthnEventIds.NO_CREDENTIALS);
            return;
        }

        if (! foundLower) {
            log.info("{} Rejecting new password since it does not contain a lower case letter", getLogPrefix());
            authErrorContext.getClassifiedErrors().add("Password must contain a lower case letter");
            ActionSupport.buildEvent(profileRequestContext, AuthnEventIds.NO_CREDENTIALS);
            return;
        }

        LDAPResponseContext ldapResponseContext = authenticationContext.getSubcontext(LDAPResponseContext.class, true);
        LdapEntry ldapEntry = ldapResponseContext.getAuthenticationResponse().getLdapEntry();
        String userDn = ldapEntry.getDn();
        log.debug("{} The user DN is {}", getLogPrefix(), userDn);

        Connection ldapConnection = null;

        try {
            ldapConnection = connectionFactory.getConnection();
        } catch (LdapException e) {
            log.error("{} Unable to get connection to LDAP: {}", getLogPrefix(), e);
            ActionSupport.buildEvent(profileRequestContext, AuthnEventIds.NO_CREDENTIALS);
            return;
        }

        try {
            ldapConnection.open();
            ModifyOperation modify = new ModifyOperation(ldapConnection);
            modify.execute(
                new ModifyRequest(userDn,
                    new AttributeModification(AttributeModificationType.REPLACE,
                        new LdapAttribute("userPassword", newPassword))));
            log.info("{} Successfully set the userPassword attribute for {}", getLogPrefix(), userDn);
        } catch (LdapException e) {
            log.error("{} Unable to modify DN {}: {}", getLogPrefix(), userDn, e);
            ActionSupport.buildEvent(profileRequestContext, AuthnEventIds.NO_CREDENTIALS);
            return;
        } finally {
            ldapConnection.close();
        }

        log.debug("{} Done extracting password for reset.");
    }
}
