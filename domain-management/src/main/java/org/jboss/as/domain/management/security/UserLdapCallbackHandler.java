/*
 * JBoss, Home of Professional Open Source.
 * Copyright 2011, Red Hat, Inc., and individual contributors
 * as indicated by the @author tags. See the copyright.txt file in the
 * distribution for a full listing of individual contributors.
 *
 * This is free software; you can redistribute it and/or modify it
 * under the terms of the GNU Lesser General Public License as
 * published by the Free Software Foundation; either version 2.1 of
 * the License, or (at your option) any later version.
 *
 * This software is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the GNU
 * Lesser General Public License for more details.
 *
 * You should have received a copy of the GNU Lesser General Public
 * License along with this software; if not, write to the Free
 * Software Foundation, Inc., 51 Franklin St, Fifth Floor, Boston, MA
 * 02110-1301 USA, or see the FSF site: http://www.fsf.org.
 */

package org.jboss.as.domain.management.security;

import static org.jboss.as.domain.management.logging.DomainManagementLogger.SECURITY_LOGGER;
import static org.jboss.as.domain.management.RealmConfigurationConstants.VERIFY_PASSWORD_CALLBACK_SUPPORTED;
import static org.wildfly.common.Assert.checkNotNullParam;

import java.io.IOException;
import java.net.URI;
import java.util.Collections;
import java.util.HashMap;
import java.util.Map;
import java.util.Set;

import javax.naming.NamingException;
import javax.security.auth.callback.Callback;
import javax.security.auth.callback.CallbackHandler;
import javax.security.auth.callback.NameCallback;
import javax.security.auth.callback.UnsupportedCallbackException;
import javax.security.sasl.AuthorizeCallback;
import javax.security.sasl.RealmCallback;

import org.jboss.as.domain.management.AuthMechanism;
import org.jboss.as.domain.management.logging.DomainManagementLogger;
import org.jboss.as.domain.management.SecurityRealm;
import org.jboss.as.domain.management.connections.ldap.LdapConnectionManager;
import org.jboss.as.domain.management.security.LdapSearcherCache.AttachmentKey;
import org.jboss.as.domain.management.security.LdapSearcherCache.SearchResult;
import org.jboss.msc.inject.Injector;
import org.jboss.msc.service.Service;
import org.jboss.msc.service.ServiceName;
import org.jboss.msc.service.StartContext;
import org.jboss.msc.service.StartException;
import org.jboss.msc.service.StopContext;
import org.jboss.msc.value.InjectedValue;
import org.wildfly.security.auth.SupportLevel;
import org.wildfly.security.auth.callback.EvidenceVerifyCallback;
import org.wildfly.security.auth.server.IdentityLocator;
import org.wildfly.security.auth.server.RealmIdentity;
import org.wildfly.security.auth.server.RealmUnavailableException;
import org.wildfly.security.credential.Credential;
import org.wildfly.security.evidence.Evidence;
import org.wildfly.security.evidence.PasswordGuessEvidence;

/**
 * A CallbackHandler for users within an LDAP directory.
 *
 * @author <a href="mailto:darran.lofthouse@jboss.com">Darran Lofthouse</a>
 */
public class UserLdapCallbackHandler implements Service<CallbackHandlerService>, CallbackHandlerService {

    private static final AttachmentKey<PasswordCredential> PASSWORD_KEY = AttachmentKey.create(PasswordCredential.class);

    private static final String SERVICE_SUFFIX = "ldap";

    public static final String DEFAULT_USER_DN = "dn";

    private final InjectedValue<LdapConnectionManager> connectionManager = new InjectedValue<LdapConnectionManager>();
    private final InjectedValue<LdapSearcherCache<LdapEntry, String>> userSearcherInjector = new InjectedValue<LdapSearcherCache<LdapEntry, String>>();

    private final boolean allowEmptyPassword;
    private final boolean shareConnection;
    protected final int searchTimeLimit = 10000; // TODO - Maybe make configurable.

    public UserLdapCallbackHandler(boolean allowEmptyPassword, boolean shareConnection) {
        this.allowEmptyPassword = allowEmptyPassword;
        this.shareConnection = shareConnection;
    }

    /*
     * CallbackHandlerService Methods
     */

    public AuthMechanism getPreferredMechanism() {
        return AuthMechanism.PLAIN;
    }

    public Set<AuthMechanism> getSupplementaryMechanisms() {
        return Collections.emptySet();
    }

    public Map<String, String> getConfigurationOptions() {
        return Collections.singletonMap(VERIFY_PASSWORD_CALLBACK_SUPPORTED, Boolean.TRUE.toString());
    }


    @Override
    public boolean isReadyForHttpChallenge() {
        // Configured for LDAP so assume we have some users.
        return true;
    }

    public CallbackHandler getCallbackHandler(Map<String, Object> sharedState) {
        return new LdapCallbackHandler(sharedState);
    }

    @Override
    public org.wildfly.security.auth.server.SecurityRealm getElytronSecurityRealm() {
        return new SecurityRealmImpl();
    }

    /*
     *  Service Methods
     */

    public void start(StartContext context) throws StartException {
    }

    public void stop(StopContext context) {
    }

    public CallbackHandlerService getValue() throws IllegalStateException, IllegalArgumentException {
        return this;
    }

    /*
     *  Access to Injectors
     */

    public InjectedValue<LdapConnectionManager> getConnectionManagerInjector() {
        return connectionManager;
    }

    public Injector<LdapSearcherCache<LdapEntry, String>> getLdapUserSearcherInjector() {
        return userSearcherInjector;
    }

    private LdapConnectionHandler createLdapConnectionHandler() {
        LdapConnectionManager connectionManager = this.connectionManager.getValue();

        return LdapConnectionHandler.newInstance(connectionManager);
    }

    /*
     *  CallbackHandler Method
     */

    private class LdapCallbackHandler implements CallbackHandler {

        private final Map<String, Object> sharedState;

        private LdapCallbackHandler(final Map<String, Object> sharedState) {
            this.sharedState = sharedState;
        }

        public void handle(Callback[] callbacks) throws IOException, UnsupportedCallbackException {
            if (callbacks.length == 1 && callbacks[0] instanceof AuthorizeCallback) {
                AuthorizeCallback acb = (AuthorizeCallback) callbacks[0];
                String authenticationId = acb.getAuthenticationID();
                String authorizationId = acb.getAuthorizationID();
                boolean authorized = authenticationId.equals(authorizationId);
                if (authorized == false) {
                    SECURITY_LOGGER.tracef(
                            "Checking 'AuthorizeCallback', authorized=false, authenticationID=%s, authorizationID=%s.",
                            authenticationId, authorizationId);
                }
                acb.setAuthorized(authorized);

                return;
            }


            EvidenceVerifyCallback evidenceVerifyCallback = null;
            String username = null;

            for (Callback current : callbacks) {
                if (current instanceof NameCallback) {
                    username = ((NameCallback) current).getDefaultName();
                } else if (current instanceof RealmCallback) {
                    // TODO - Nothing at the moment
                } else if (current instanceof EvidenceVerifyCallback) {
                    evidenceVerifyCallback = (EvidenceVerifyCallback) current;
                } else {
                    throw new UnsupportedCallbackException(current);
                }
            }

            if (username == null || username.length() == 0) {
                SECURITY_LOGGER.trace("No username or 0 length username supplied.");
                throw DomainManagementLogger.ROOT_LOGGER.noUsername();
            }
            if (evidenceVerifyCallback == null || evidenceVerifyCallback.getEvidence() == null) {
                SECURITY_LOGGER.trace("No password to verify.");
                throw DomainManagementLogger.ROOT_LOGGER.noPassword();
            }

            final String password;

            if (evidenceVerifyCallback.getEvidence() instanceof PasswordGuessEvidence) {
                 char[] guess = ((PasswordGuessEvidence) evidenceVerifyCallback.getEvidence()).getGuess();
                 password = guess != null ? new String(guess) : null;
            } else {
                password = null;
            }

            if (password == null || (allowEmptyPassword == false && password.length() == 0)) {
                SECURITY_LOGGER.trace("No password or 0 length password supplied.");
                throw DomainManagementLogger.ROOT_LOGGER.noPassword();
            }


            LdapConnectionHandler lch = createLdapConnectionHandler();
            try {
                // 2 - Search to identify the DN of the user connecting
                SearchResult<LdapEntry> searchResult = userSearcherInjector.getValue().search(lch, username);

                evidenceVerifyCallback.setVerified(verifyPassword(lch, searchResult, username, password, sharedState));
            } catch (Exception e) {
                SECURITY_LOGGER.trace("Unable to verify identity.", e);
                throw DomainManagementLogger.ROOT_LOGGER.cannotPerformVerification(e);
            } finally {
                if (shareConnection && lch != null && evidenceVerifyCallback != null && evidenceVerifyCallback.isVerified()) {
                    sharedState.put(LdapConnectionHandler.class.getName(), lch);
                } else {
                    lch.close();
                }
            }
        }
    }

    private static boolean verifyPassword(LdapConnectionHandler ldapConnectionHandler, SearchResult<LdapEntry> searchResult, String username, String password, Map<String, Object> sharedState) {
        LdapEntry ldapEntry = searchResult.getResult();

        // 3 - Connect as user once their DN is identified
        final PasswordCredential cachedCredential = searchResult.getAttachment(PASSWORD_KEY);
        if (cachedCredential != null) {
            if (cachedCredential.verify(password)) {
                SECURITY_LOGGER.tracef("Password verified for user '%s' (using cached password)", username);

                sharedState.put(LdapEntry.class.getName(), ldapEntry);
                if (username.equals(ldapEntry.getSimpleName()) == false) {
                    sharedState.put(SecurityRealmService.LOADED_USERNAME_KEY, ldapEntry.getSimpleName());
                }
                return true;
            } else {
                SECURITY_LOGGER.tracef("Password verification failed for user (using cached password) '%s'", username);
                return false;
            }
        } else {
            try {
                LdapConnectionHandler verificationHandler = ldapConnectionHandler;
                URI referralUri = ldapEntry.getReferralUri();
                if (referralUri != null) {
                    verificationHandler = verificationHandler.findForReferral(referralUri);
                }

                if (verificationHandler != null) {
                    verificationHandler.verifyIdentity(ldapEntry.getDistinguishedName(), password);
                    SECURITY_LOGGER.tracef("Password verified for user '%s' (using connection attempt)", username);

                    searchResult.attach(PASSWORD_KEY, new PasswordCredential(password));
                    sharedState.put(LdapEntry.class.getName(), ldapEntry);
                    if (username.equals(ldapEntry.getSimpleName()) == false) {
                        sharedState.put(SecurityRealmService.LOADED_USERNAME_KEY, ldapEntry.getSimpleName());
                    }
                    return true;
                } else {
                    SECURITY_LOGGER.tracef(
                            "Password verification failed for user '%s', no connection for referral '%s'", username,
                            referralUri.toString());
                    return false;
                }
            } catch (Exception e) {
                SECURITY_LOGGER.tracef("Password verification failed for user (using connection attempt) '%s'",
                        username);
                return false;
            }
        }
    }

    private void safeClose(LdapConnectionHandler ldapConnectionHandler) {
        try {
            if (ldapConnectionHandler != null) {
                ldapConnectionHandler.close();
            }
        } catch (IOException e) {
            SECURITY_LOGGER.trace("Unable to close ldapConnectionHandler", e);
        }
    }

    private class SecurityRealmImpl implements org.wildfly.security.auth.server.SecurityRealm {

        @Override
        public RealmIdentity getRealmIdentity(IdentityLocator locator) throws RealmUnavailableException {
            final String name;
            if (locator.hasName() == false || (name = locator.getName()).length() == 0) {
                return RealmIdentity.NON_EXISTENT;
            }

            LdapConnectionHandler ldapConnectionHandler = createLdapConnectionHandler();

            try {
                SearchResult<LdapEntry> searchResult = userSearcherInjector.getValue().search(ldapConnectionHandler, name);

                return new RealmIdentityImpl(name, ldapConnectionHandler, searchResult, SecurityRealmService.SharedStateSecurityRealm.getSharedState());
            } catch (IllegalStateException e) {
                safeClose(ldapConnectionHandler);
                return RealmIdentity.NON_EXISTENT;
            } catch (IOException | NamingException e) {
                safeClose(ldapConnectionHandler);
                throw new RealmUnavailableException(e);
            }
        }

        @Override
        public SupportLevel getCredentialAcquireSupport(Class<? extends Credential> credentialType, String algorithmName) throws RealmUnavailableException {
            return SupportLevel.UNSUPPORTED;
        }

        @Override
        public SupportLevel getEvidenceVerifySupport(Class<? extends Evidence> evidenceType, String algorithmName) throws RealmUnavailableException {
            checkNotNullParam("evidenceType", evidenceType);
            return PasswordGuessEvidence.class.isAssignableFrom(evidenceType) ? SupportLevel.SUPPORTED : SupportLevel.UNSUPPORTED;
        }

        private class RealmIdentityImpl implements RealmIdentity {

            private final String username;
            private final LdapConnectionHandler ldapConnectionHandler;
            private final SearchResult<LdapEntry> searchResult;
            private final Map<String, Object> sharedState;

            private RealmIdentityImpl(final String username, final LdapConnectionHandler ldapConnectionHandler, final SearchResult<LdapEntry> searchResult, final Map<String, Object> sharedState) {
                this.username = username;
                this.ldapConnectionHandler = ldapConnectionHandler;
                this.searchResult = searchResult;
                this.sharedState = sharedState != null ? sharedState : new HashMap<>();
            }

            @Override
            public SupportLevel getCredentialAcquireSupport(Class<? extends Credential> credentialType, String algorithmName)throws RealmUnavailableException {
                return SecurityRealmImpl.this.getCredentialAcquireSupport(credentialType, algorithmName);
            }

            @Override
            public <C extends Credential> C getCredential(Class<C> credentialType) throws RealmUnavailableException {
                return null;
            }

            @Override
            public SupportLevel getEvidenceVerifySupport(Class<? extends Evidence> evidenceType, String algorithmName)throws RealmUnavailableException {
                return SecurityRealmImpl.this.getEvidenceVerifySupport(evidenceType, algorithmName);
            }

            @Override
            public boolean verifyEvidence(Evidence evidence) throws RealmUnavailableException {
                if (evidence instanceof PasswordGuessEvidence) {
                    PasswordGuessEvidence passwordGuessEvidence = (PasswordGuessEvidence) evidence;
                    char[] guess =passwordGuessEvidence.getGuess();

                    if (guess == null || (allowEmptyPassword == false && guess.length == 0)) {
                        SECURITY_LOGGER.trace("No password or 0 length password supplied.");
                        return false;
                    }

                    boolean result = verifyPassword(ldapConnectionHandler, searchResult, username, new String(guess), sharedState);
                    if (shareConnection && result) {
                        sharedState.put(LdapConnectionHandler.class.getName(), ldapConnectionHandler);
                    }
                    return result;
                }
                return false;
            }

            @Override
            public boolean exists() throws RealmUnavailableException {
                return true;
            }

            @Override
            public void dispose() {
                safeClose(ldapConnectionHandler);
            }

        }
    }

    public static final class ServiceUtil {

        private ServiceUtil() {
        }

        public static ServiceName createServiceName(final String realmName) {
            return SecurityRealm.ServiceUtil.createServiceName(realmName).append(SERVICE_SUFFIX);
        }

    }

    private static final class PasswordCredential {

        private final String password;

        private PasswordCredential(final String password) {
            this.password = password;
        }

        private boolean verify(final String password) {
            return this.password.equals(password);
        }
    }

}
