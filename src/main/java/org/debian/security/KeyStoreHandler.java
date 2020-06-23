/*
 * Copyright (C) 2011 Torsten Werner <twerner@debian.org>
 * Copyright (C) 2012 Damien Raude-Morvan <drazzib@debian.org>
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 2 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License along
 * with this program; if not, write to the Free Software Foundation, Inc.,
 * 51 Franklin Street, Fifth Floor, Boston, MA 02110-1301 USA.
 */

package org.debian.security;

import java.io.File;
import java.io.FileInputStream;
import java.io.FileOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.security.GeneralSecurityException;
import java.security.KeyStore;
import java.security.KeyStoreException;
import java.security.cert.Certificate;
import java.security.cert.CertificateFactory;

/**
 * Handles read/write operations on a keystore.
 */
class KeyStoreHandler {

    /**
     * The path of the keystore
     */
    private final String filename;

    /**
     * The password of the keystore
     */
    private final char[] password;
    private final CertificateFactory certFactory;
    private KeyStore keyStore;

    KeyStoreHandler(final String filename, final char[] password) throws GeneralSecurityException, InvalidKeystorePasswordException, IOException {
        this.filename = filename;
        this.password = password;
        this.certFactory = CertificateFactory.getInstance("X.509");

        this.load();
    }

    /**
     * Try to open an existing keystore or create an new one.
     */
    public void load() throws GeneralSecurityException, InvalidKeystorePasswordException, IOException {
        final KeyStore keyStore = KeyStore.getInstance("JKS");

        final File file = new File(this.filename);
        if (!file.exists() || !file.canRead()) {
            keyStore.load(null, this.password);
        } else {
            try (InputStream inputStream = new FileInputStream(this.filename)) {
                keyStore.load(inputStream, this.password);
            } catch (IOException e) {
                throw new InvalidKeystorePasswordException("Cannot open Java keystore. Is the password correct?", e);
            }
        }

        this.keyStore = keyStore;
    }

    /**
     * Write actual keystore content to disk.
     */
    public void save() throws GeneralSecurityException, UnableToSaveKeystoreException {
        try (OutputStream outputStream = new FileOutputStream(this.filename)) {
            this.keyStore.store(outputStream, this.password);
        } catch (IOException e) {
            throw new UnableToSaveKeystoreException("There was a problem saving the new Java keystore.", e);
        }
    }

    /**
     * Add or replace existing cert in keystore with given alias.
     */
    public void addAlias(final String alias, final String path) throws KeyStoreException {
        final Certificate cert = this.loadCertificate(path);
        if (cert != null) {
            this.addAlias(alias, cert);
        }
    }

    /**
     * Add or replace existing cert in keystore with given alias.
     */
    public void addAlias(final String alias, final Certificate cert) throws KeyStoreException {
        if (this.contains(alias)) {
            System.out.println("Replacing " + alias);
            this.keyStore.deleteEntry(alias);
        } else System.out.println("Adding " + alias);
        this.keyStore.setCertificateEntry(alias, cert);
    }

    /**
     * Delete cert in keystore at given alias.
     */
    public void deleteAlias(final String alias) throws GeneralSecurityException {
        if (this.contains(alias)) {
            System.out.println("Removing " + alias);
            this.keyStore.deleteEntry(alias);
        }
    }

    /**
     * Returns true when alias exist in keystore.
     */
    public boolean contains(String alias) throws KeyStoreException {
        return this.keyStore.containsAlias(alias);
    }

    /**
     * Try to load a certificate instance from given path.
     */
    private Certificate loadCertificate(final String path) {
        try (InputStream inputStream = new FileInputStream(path)) {
            return this.certFactory.generateCertificate(inputStream);
        } catch (Exception e) {
            System.err.println("Warning: there was a problem reading the certificate file "
                    + path + ". Message:\n  " + e.getMessage());
            return null;
        }
    }
}
