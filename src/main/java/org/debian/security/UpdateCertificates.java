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

import java.io.BufferedReader;
import java.io.IOException;
import java.io.InputStreamReader;
import java.io.Reader;
import java.nio.charset.StandardCharsets;
import java.security.GeneralSecurityException;

/**
 * This code is a re-implementation of the idea from Ludwig Nussel found in
 * https://github.com/openSUSE/ca-certificates/blob/41917f5a/keystore.java
 * for the Debian operating system. It updates the global JVM keystore.
 *
 * @author Torsten Werner
 * @author Damien Raude-Morvan
 */
public class UpdateCertificates {

    private final KeyStoreHandler keystore;

    public UpdateCertificates(final String keystoreFile, final String password) throws IOException, GeneralSecurityException, InvalidKeystorePasswordException {
        this.keystore = new KeyStoreHandler(keystoreFile, password.toCharArray());
    }

    public static void main(final String[] args) throws IOException, GeneralSecurityException {
        String passwordString = "changeit";

        if (args.length == 2 && args[0].equals("--storepass")) {
            passwordString = args[1];
        } else if (args.length > 0) {
            System.err.println("Usage: java [--storepass <password>]");
            System.exit(1);
        }

        try {
            final UpdateCertificates uc = new UpdateCertificates(System.getenv("JAVA_HOME") + "/lib/security/cacerts", passwordString);
            // Force reading of InputStream in UTF-8
            uc.processChanges(new InputStreamReader(System.in, StandardCharsets.UTF_8));
            uc.finish();
        } catch (InvalidKeystorePasswordException | UnableToSaveKeystoreException e) {
            e.printStackTrace();
            System.exit(1);
        }
    }

    /**
     * Until reader EOF, try to read changes and send each to {@link #parseLine(String)}.
     */
    protected void processChanges(final Reader reader) throws IOException, GeneralSecurityException {
        String line;
        try (BufferedReader br = new BufferedReader(reader)) {
            while ((line = br.readLine()) != null) {
                try {
                    this.parseLine(line);
                } catch (UnknownInputException e) {
                    System.err.println("Unknown input: " + line);
                    // Keep processing for others lines
                }
            }
        }
    }

    protected void parseLine(final String line) throws GeneralSecurityException, UnknownInputException {
        if (line.isBlank()) return;

        final String path = line.substring(1);
        final String filename = path.substring(path.lastIndexOf("/") + 1);
        final String alias = "debian:" + filename;

        if (line.startsWith("+")) this.keystore.addAlias(alias, path);
        else if (line.startsWith("-")) {
            this.keystore.deleteAlias(alias);
            this.keystore.deleteAlias(filename);
        } else throw new UnknownInputException(line);
    }

    /**
     * Write the pending changes to the keystore file.
     */
    protected void finish() throws GeneralSecurityException, UnableToSaveKeystoreException {
        this.keystore.save();
    }
}
