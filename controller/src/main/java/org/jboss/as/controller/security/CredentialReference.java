/*
 * JBoss, Home of Professional Open Source
 * Copyright 2016 Red Hat, Inc., and individual contributors
 * as indicated by the @author tags.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */
package org.jboss.as.controller.security;

import org.jboss.as.controller.ObjectTypeAttributeDefinition;
import org.jboss.as.controller.OperationContext;
import org.jboss.as.controller.OperationFailedException;
import org.jboss.as.controller.SimpleAttributeDefinition;
import org.jboss.as.controller.SimpleAttributeDefinitionBuilder;
import org.jboss.dmr.ModelNode;
import org.jboss.dmr.ModelType;
import org.jboss.msc.value.InjectedValue;

import javax.security.auth.DestroyFailedException;
import javax.security.auth.Destroyable;

/**
 * Class unifying access to credentials defined through {@link org.wildfly.security.credential.store.CredentialStore}
 * or holding simply {@code char[]} as a secret.
 *
 * It defines credential reference attribute that other subsystems can use to reference external credentials of various
 * types.
 *
 * @author <a href="mailto:pskopek@redhat.com">Peter Skopek</a>
 */
public final class CredentialReference implements Destroyable {

    /**
     * Definition of id used in model
     */
    public static final String CREDENTIAL_REFERENCE = "credential-reference";
    /**
     * Definition of id used in model
     */
    public static final String CREDENTIAL_STORE = "credential-store";
    /**
     * Definition of id used in model
     */
    public static final String CREDENTIAL_ALIAS = "credential-alias";
    /**
     * Definition of id used in model
     */
    public static final String CREDENTIAL_TYPE = "credential-type";
    /**
     * Definition of id used in model
     */
    public static final String CLEAR_TEXT = "clear-text";

    static final SimpleAttributeDefinition credentialStoreAttribute = new SimpleAttributeDefinitionBuilder(CREDENTIAL_STORE, ModelType.STRING, true).build();
    static final SimpleAttributeDefinition credentialAliasAttribute = new SimpleAttributeDefinitionBuilder(CREDENTIAL_ALIAS, ModelType.STRING, false).build();
    static final SimpleAttributeDefinition credentialTypeAttribute = new SimpleAttributeDefinitionBuilder(CREDENTIAL_TYPE, ModelType.STRING, true).build();
    static final SimpleAttributeDefinition clearTextAttribute = new SimpleAttributeDefinitionBuilder(CLEAR_TEXT, ModelType.STRING, true).build();

    private final String credentialStoreName;
    private final String alias;
    private final String credentialType;
    private char[] secret;

    private CredentialReference(String credentialStoreName, String alias, String credentialType, char[] secret) {
        this.credentialStoreName = credentialStoreName;
        this.alias = alias;
        this.credentialType = credentialType;
        if (secret != null) {
            this.secret = secret.clone();
        } else {
            this.secret = null;
        }
    }

    /**
     * Get the credential store name part of this reference.
     * @return credential store name
     */
    public String getCredentialStoreName() {
        return credentialStoreName;
    }

    /**
     * Get the credential alias which denotes credential stored inside named credential store.
     * @return alias of the referenced credential
     */
    public String getAlias() {
        return alias;
    }

    /**
     * Get credential type which narrows selection of the credential stored under the alias in the credential store.
     * @return credential type (class name of desired credential type)
     */
    public String getCredentialType() {
        return credentialType;
    }

    /**
     * Get the secret stored as clear text in this reference.
     * @return secret value as clear text
     */
    public char[] getSecret() {
        return secret;
    }


    /**
     * Destroy this {@code Object}.
     * <p>
     * <p> Sensitive information associated with this {@code Object}
     * is destroyed or cleared.  Subsequent calls to certain methods
     * on this {@code Object} will result in an
     * {@code IllegalStateException} being thrown.
     * <p>
     * <p>
     * The default implementation throws {@code DestroyFailedException}.
     *
     * @throws DestroyFailedException if the destroy operation fails. <p>
     * @throws SecurityException      if the caller does not have permission
     *                                to destroy this {@code Object}.
     */
    @Override
    public void destroy() throws DestroyFailedException {
        if (secret != null) {
            for (int i = 0; i < secret.length; i++) {
                secret[i] = 0;
            }
            secret = null;
        }
    }

    /**
     * Determine if this {@code Object} has been destroyed.
     * <p>
     * <p>
     * The default implementation returns false.
     *
     * @return true if this {@code Object} has been destroyed,
     * false otherwise.
     */
    @Override
    public boolean isDestroyed() {
        return secret == null;
    }

    // factory static methods

    /**
     * Method to create new {@link CredentialReference} based on {@link #secret} attribute only.
     * @param secret to reference
     * @return new {@link CredentialReference}
     */
    public static CredentialReference createCredentialReference(char[] secret) {
        return new CredentialReference(CredentialReference.class.getName(), null, null, secret);
    }

    /**
     * Method to create new {@link CredentialReference} based on params
     * @param credentialStoreName credential store name
     * @param alias denoting the credential
     * @param credentialType type of credential (can be {@code null})
     * @return new {@link CredentialReference}
     */
    public static CredentialReference createCredentialReference(String credentialStoreName, String alias, String credentialType) {
        return new CredentialReference(credentialStoreName, alias, credentialType, null);
    }

    // utility static methods

    /**
     * Returns new definition for credential reference attribute.
     *
     * @return credential reference attribute definition
     */
    public static ObjectTypeAttributeDefinition getAttributeDefinition() {
        return new ObjectTypeAttributeDefinition.Builder(CREDENTIAL_REFERENCE, credentialStoreAttribute, credentialAliasAttribute, credentialTypeAttribute, clearTextAttribute)
                .build();
    }

    /**
     * Utility method to return part of {@link ObjectTypeAttributeDefinition} for credential reference attribute.
     *
     * {@see CredentialReference#getAttributeDefinition}
     * @param context operational context
     * @param attributeDefinition attribute definition
     * @param model model
     * @param name name of part to return (supported names: {@link #CREDENTIAL_STORE} {@link #CREDENTIAL_ALIAS} {@link #CREDENTIAL_TYPE}
     *    {@link #CLEAR_TEXT}
     * @return value of part as {@link String}
     * @throws OperationFailedException when something goes wrong
     */
    public static String credentialReferencePartAsStringIfDefined(OperationContext context, ObjectTypeAttributeDefinition attributeDefinition, ModelNode model, String name) throws OperationFailedException {
        ModelNode value = attributeDefinition.resolveModelAttribute(context, model);
        if (value.isDefined()) {
            ModelNode namedNode = value.get(name);
            if (namedNode != null && namedNode.isDefined()) {
                return namedNode.asString();
            }
            return null;
        }
        return null;
    }

    /**
     * Replace injection with new one referencing the same {@link org.wildfly.security.credential.store.CredentialStore} but
     * based of new values of {@link CredentialReference}
     * @param injectedCredentialStoreClient {@link InjectedValue} to replace the credential reference
     * @param credentialReference new credential reference
     * @throws ClassNotFoundException when credential reference holding credential type which cannot be resolved using current providers
     */
    public static void reinjectCredentialStoreClient(InjectedValue<CredentialStoreClient> injectedCredentialStoreClient,
            CredentialReference credentialReference) throws ClassNotFoundException {

        CredentialStoreClient originalCredentialStoreClient = injectedCredentialStoreClient.getValue();
        final CredentialStoreClient updatedCredentialStoreClient =
                credentialReference.getCredentialType() != null
                ?
                new CredentialStoreClient(
                    originalCredentialStoreClient.getCredentialStore(),
                    credentialReference.getCredentialStoreName(),
                    credentialReference.getAlias(),
                    credentialReference.getCredentialType())
                :
                new CredentialStoreClient(
                        originalCredentialStoreClient.getCredentialStore(),
                        credentialReference.getCredentialStoreName(),
                        credentialReference.getAlias());

        injectedCredentialStoreClient.setValue(() -> updatedCredentialStoreClient);
    }

}
