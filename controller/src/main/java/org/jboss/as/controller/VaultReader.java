/*
* JBoss, Home of Professional Open Source.
* Copyright 2011, Red Hat Middleware LLC, and individual contributors
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
package org.jboss.as.controller;

import java.util.regex.Pattern;

/**
 * Provides access to data stored in a vault, by means of passing in "vaulted data" generated when the data
 * was stored in the vault. While different vault reader implementations may use vaults with a different format,
 * the standard format for vaulted data is {@code VAULT::vault_block::attribute_name::sharedKey}, where
 * <ol>
 * <li>{@code vault_block} acts as the unique id of a block, such as "messaging", "security" etc.</li>
 * <li>{@code attribute_name} is the name of the attribute whose value was stored</li>
 * <li>{@code sharedKey} is the key generated by the off line vault during storage of the attribute value.</li>
 * </ol>
 *
 * @author <a href="kabir.khan@jboss.com">Kabir Khan</a>
 */
public interface VaultReader {

    /**
     * Pattern that describes the standard "vaulted data" format.
     */
    Pattern STANDARD_VAULT_PATTERN = Pattern.compile("VAULT::.*::.*::.*");

    /**
     * Returns whether the given string is in the correct "vaulted data" format. See the class description
     * for details on the format of "vaulted data".
     * @param toCheck the string to check. May be {@code null}
     * @return {@code true} if {@code toCheck} is a non-null string in vaulted data format.
     */
    boolean isVaultFormat(String toCheck);

    /**
     * Returns the data stored in the vault that is indicated by the given "vaulted data". See the class description
     * for details on the format of "vaulted data".
     *
     * @param vaultedData the possible vaulted data. May also be {@code null}, or a string that is not in the vaulted data format
     * @return the data stored in the vault, or the original data if {@code vaultedData} is not properly formatted
     *         vaulted data
     *
     * @throws NoSuchItemException if {@code vaultedData} is properly formatted but the item indicated by it
     *                             is not stored in a vault accessible to this vault reader
     *
     * @throws RuntimeException if there is a problem accessing the vault
     */
    String retrieveFromVault(String vaultedData);

    /**
     * Exception thrown when properly formatted "vaulted data" is used to retrieve data from the vault but
     * no matching data can be found.
     */
    final class NoSuchItemException extends RuntimeException {

    }

}
