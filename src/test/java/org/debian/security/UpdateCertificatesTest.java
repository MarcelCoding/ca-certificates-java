/*
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

import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

import java.io.File;
import java.io.StringReader;

import static org.junit.jupiter.api.Assertions.*;

/**
 * Tests for {@link UpdateCertificates}.
 *
 * @author Damien Raude-Morvan
 */
public class UpdateCertificatesTest {

    private static final String CERT_ALIAS = "debian:spi-cacert-2008.crt";
    private static final String CERT_PATH = "target/test-classes/spi-cacert-2008.crt";
    private static final String INVALID_CERT_CMD = "x" + CERT_PATH;
    private static final String REMOVE_CERT_CMD = "-" + CERT_PATH;
    private static final String ADD_CERT_CMD = "+" + CERT_PATH;

    private final String filename = "./target/test-classes";
    private final String password = "changeit";

    @BeforeEach
    public void start() {
        // Delete any previous file
        new File(this.filename).delete();
    }

    /**
     * Try to send an invalid command ("x") in parseLine : throw UnknownInput
     */
    @Test
    public void testWrongCommand() throws Exception {
        try {
            new UpdateCertificates(this.filename, this.password).parseLine(INVALID_CERT_CMD);
            fail();
        } catch (UnknownInputException e) {
            assertEquals(INVALID_CERT_CMD, e.getMessage());
        }
    }

    /**
     * Test to insert a valid certificate and then check if it's really in KS.
     */
    @Test
    public void testAdd() throws Exception {
        final UpdateCertificates uc = new UpdateCertificates(this.filename, this.password);
        uc.parseLine(ADD_CERT_CMD);
        uc.finish();

        final KeyStoreHandler keystore = new KeyStoreHandler(this.filename, this.password.toCharArray());
        assertTrue(keystore.contains(CERT_ALIAS));
    }

    /**
     * Test to insert a invalide certificate : no exception, but check there
     * is no alias created with that name
     */
    @Test
    public void testAddInvalidCert() throws Exception {
        final UpdateCertificates uc = new UpdateCertificates(this.filename, this.password);
        uc.parseLine("+/usr/share/ca-certificates/null.crt");
        uc.finish();

        assertFalse(new KeyStoreHandler(this.filename, this.password.toCharArray())
                .contains("debian:null.crt"));
    }

    /**
     * Test to insert a certificate with a comment (Bug #539283)
     */
    @Test
    public void testAddCertWithComment() throws Exception {
        final UpdateCertificates uc = new UpdateCertificates(this.filename, this.password);
        uc.parseLine("+target/test-classes/spi-cacert-2008-with-comment.crt");
        uc.finish();

        assertTrue(new KeyStoreHandler(this.filename, this.password.toCharArray())
                .contains("debian:spi-cacert-2008-with-comment.crt"));
    }

    /**
     * Try to add same certificate multiple time : we replace it and
     * there is only one alias.
     */
    @Test
    public void testReplace() throws Exception {
        final UpdateCertificates uc = new UpdateCertificates(this.filename, this.password);
        uc.parseLine(ADD_CERT_CMD);
        uc.parseLine(ADD_CERT_CMD);
        uc.finish();

        assertTrue(new KeyStoreHandler(this.filename, this.password.toCharArray())
                .contains(CERT_ALIAS));
    }

    /**
     * Try to remove a non-existant certificate : it's a no-op.
     */
    @Test
    public void testRemove() throws Exception {
        final UpdateCertificates uc = new UpdateCertificates(this.filename, this.password);
        uc.parseLine(REMOVE_CERT_CMD);
        uc.finish();

        // We start with empty KS, so it shouldn't do anything
        assertFalse(new KeyStoreHandler(this.filename, this.password.toCharArray())
                .contains(CERT_ALIAS));
    }

    /**
     * Try to add cert, write to disk, then open keystore again and remove.
     */
    @Test
    public void testAddThenRemove() throws Exception {
        final UpdateCertificates ucAdd = new UpdateCertificates(this.filename, this.password);
        ucAdd.parseLine(ADD_CERT_CMD);
        ucAdd.finish();

        final KeyStoreHandler keystore = new KeyStoreHandler(this.filename, this.password.toCharArray());
        assertTrue(keystore.contains(CERT_ALIAS));

        final UpdateCertificates ucRemove = new UpdateCertificates(this.filename, this.password);
        ucRemove.parseLine(REMOVE_CERT_CMD);
        ucRemove.finish();

        keystore.load();
        assertFalse(keystore.contains(CERT_ALIAS));
    }

    @Test
    public void testProcessChanges() throws Exception {
        final UpdateCertificates uc = new UpdateCertificates(this.filename, this.password);
        uc.processChanges(new StringReader(ADD_CERT_CMD + "\n" + INVALID_CERT_CMD + "\n" + REMOVE_CERT_CMD + "\n"));
        uc.finish();

        assertFalse(new KeyStoreHandler(this.filename, this.password.toCharArray())
                .contains(CERT_ALIAS));
    }
}
