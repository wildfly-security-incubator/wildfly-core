/*
 * JBoss, Home of Professional Open Source.
 * Copyright 2017 Red Hat, Inc., and individual contributors
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

package org.wildfly.extension.elytron;

import java.io.IOException;
import java.util.Collections;
import java.util.LinkedHashSet;
import java.util.Set;
import java.util.stream.Collectors;

import org.jboss.as.controller.PathElement;
import org.jboss.as.controller.registry.DelegatingResource;
import org.jboss.as.controller.registry.PlaceholderResource;
import org.jboss.as.controller.registry.Resource;
import org.jboss.msc.service.ServiceController;
import org.jboss.msc.service.ServiceController.State;
import org.wildfly.extension.elytron._private.ElytronSubsystemMessages;
import org.wildfly.security.auth.principal.NamePrincipal;
import org.wildfly.security.auth.server.CloseableIterator;
import org.wildfly.security.auth.server.ModifiableRealmIdentity;
import org.wildfly.security.auth.server.ModifiableSecurityRealm;
import org.wildfly.security.auth.server.RealmIdentity;
import org.wildfly.security.auth.server.SecurityRealm;

import static org.wildfly.extension.elytron.ElytronDescriptionConstants.IDENTITY;

/**
 * A {@link Resource} to represent a {@link ModifiableSecurityRealm}.
 * The majority is actually model but child resources are a runtime concern.
 *
 * @author <a href="mailto:jkalina@redhat.com">Jan Kalina</a>
 * @author <a href="mailto:darran.lofthouse@jboss.com">Darran Lofthouse</a>
 */
class RealmResource extends DelegatingResource {

    private ServiceController<ModifiableSecurityRealm> serviceController;

    RealmResource(Resource resource) {
        super(resource);
    }

    /**
     * Set the {@link ServiceController<ModifiableSecurityRealm>} for the {@link ModifiableSecurityRealm} represented by this {@link Resource}.
     *
     * @param serviceController The {@link ServiceController<ModifiableSecurityRealm>} to obtain the {@link ModifiableSecurityRealm} from.
     */
    public void setServiceController(ServiceController<ModifiableSecurityRealm> serviceController) {
        this.serviceController = serviceController;
    }

    @Override
    public Set<String> getChildTypes() {
        return Collections.singleton(IDENTITY);
    }

    @Override
    public boolean hasChildren(String childType) {
        final ModifiableSecurityRealm realm;
        if (!IDENTITY.equals(childType) || (realm = getSecurityRealm()) == null) return false;
        try (CloseableIterator<ModifiableRealmIdentity> it = realm.getRealmIdentityIterator()) {
            return it.hasNext();
        } catch (IOException | IllegalStateException e) {
            ElytronSubsystemMessages.ROOT_LOGGER.trace(e);
            return false;
        }
    }

    @Override
    public boolean hasChild(PathElement element) {
        final ModifiableSecurityRealm realm;
        if (!IDENTITY.equals(element.getKey()) || (realm = getSecurityRealm()) == null) return false;
        try {
            final RealmIdentity identity = realm.getRealmIdentity(new NamePrincipal(element.getValue()));
            try {
                return identity.exists();
            } finally {
                identity.dispose();
            }
        } catch (IOException | IllegalStateException e) {
            ElytronSubsystemMessages.ROOT_LOGGER.trace(e);
            return false;
        }
    }

    @Override
    public Resource getChild(PathElement element) {
        if (hasChild(element)) {
            return PlaceholderResource.INSTANCE;
        }
        return null;
    }

    @Override
    public Resource requireChild(PathElement element) {
        Resource resource = getChild(element);
        if (resource == null) {
            throw new NoSuchResourceException(element);
        }
        return resource;
    }

    @Override
    public Set<String> getChildrenNames(String childType) {
        final ModifiableSecurityRealm realm;
        if (IDENTITY.equals(childType) && (realm = getSecurityRealm()) != null) {
            try {
                Set<String> children = new LinkedHashSet<>();
                try (CloseableIterator<ModifiableRealmIdentity> iterator = realm.getRealmIdentityIterator()) {
                    while (iterator.hasNext()) {
                        ModifiableRealmIdentity identity = iterator.next();
                        children.add(identity.getRealmIdentityPrincipal().getName());
                        identity.dispose();
                    }
                }
                return children;
            } catch (IllegalStateException | IOException e) {
                ElytronSubsystemMessages.ROOT_LOGGER.trace(e);
            }
        }
        return Collections.emptySet();
    }

    @Override
    public Set<ResourceEntry> getChildren(String childType) {
        return getChildrenNames(childType).stream()
                .map((String s) -> new PlaceholderResource.PlaceholderResourceEntry(IDENTITY, s))
                .collect(Collectors.toSet());
    }

    @Override
    public Resource clone() {
        RealmResource realmResource = new RealmResource(super.clone());
        realmResource.setServiceController(serviceController);
        return realmResource;
    }

    /**
     * Get the {@link ModifiableSecurityRealm} represented by this {@link Resource} or {@code null} if it is not currently available.
     *
     * @return The {@link ModifiableSecurityRealm} represented by this {@link Resource} or {@code null} if it is not currently available.
     */
    private ModifiableSecurityRealm getSecurityRealm() {
        if (serviceController == null || serviceController.getState() != State.UP) {
            return null;
        } else {
            SecurityRealm realm = serviceController.getValue();
            return realm instanceof ModifiableSecurityRealm ? (ModifiableSecurityRealm) realm : null;
        }
    }

}
