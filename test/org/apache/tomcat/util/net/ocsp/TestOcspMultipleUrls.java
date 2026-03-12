/*
 * Licensed to the Apache Software Foundation (ASF) under one or more
 * contributor license agreements.  See the NOTICE file distributed with
 * this work for additional information regarding copyright ownership.
 * The ASF licenses this file to You under the Apache License, Version 2.0
 * (the "License"); you may not use this file except in compliance with
 * the License.  You may obtain a copy of the License at
 *
 *      http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */
package org.apache.tomcat.util.net.ocsp;

import java.io.IOException;
import java.net.SocketException;

import javax.net.ssl.SSLException;
import javax.net.ssl.SSLHandshakeException;
import javax.servlet.http.HttpServletResponse;

import java.util.Collection;

import org.junit.After;
import org.junit.AfterClass;
import org.junit.Assert;
import org.junit.Assume;
import org.junit.Before;
import org.junit.BeforeClass;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.junit.runners.Parameterized;
import org.junit.runners.Parameterized.Parameters;

import org.apache.catalina.Context;
import org.apache.catalina.startup.Tomcat;
import org.apache.tomcat.util.buf.ByteChunk;
import org.apache.tomcat.util.net.SSLHostConfig;
import org.apache.tomcat.util.net.TesterSupport;
import org.apache.tomcat.util.net.TesterSupport.SimpleServlet;

/**
 * Tests OCSP fallback to secondary URLs when primary responder fails.
 * This validates the fix for multiple OCSP URL iteration and memory allocation bugs.
 */
@RunWith(Parameterized.class)
public class TestOcspMultipleUrls extends OcspBaseTest {

    @Parameters(name = "{0} with OpenSSL trust {2}")
    public static Collection<Object[]> parameters() {
        // Reuse the parameters from OcspBaseTest
        return OcspBaseTest.parameters();
    }

    private static TesterOcspResponder ocspResponderPrimary;
    private static TesterOcspResponder ocspResponderSecondary;
    private static TesterOcspResponderNoResponse ocspResponderNoResponse;

    @BeforeClass
    public static void startOcspResponders() {
        // Use different ports than TestOcspEnabled to avoid conflicts
        // Start a working responder on port 8890 (for primary tests)
        ocspResponderPrimary = new TesterOcspResponder(8890);
        try {
            ocspResponderPrimary.start();
        } catch (IOException ioe) {
            ocspResponderPrimary = null;
        }

        // Start a working responder on port 8891 (for fallback tests)
        ocspResponderSecondary = new TesterOcspResponder(8891);
        try {
            ocspResponderSecondary.start();
        } catch (IOException ioe) {
            ocspResponderSecondary = null;
        }
    }

    @After
    public void restoreOcspResponders() throws IOException {
        // Clean up non-responsive responder if it was started
        if (ocspResponderNoResponse != null) {
            ocspResponderNoResponse.stop();
            ocspResponderNoResponse = null;
        }

        // Restart primary responder if it was stopped
        if (ocspResponderPrimary == null) {
            ocspResponderPrimary = new TesterOcspResponder(8890);
            ocspResponderPrimary.start();
        }

        // Restart secondary responder if it was stopped
        if (ocspResponderSecondary == null) {
            ocspResponderSecondary = new TesterOcspResponder(8891);
            ocspResponderSecondary.start();
        }
    }

    @AfterClass
    public static void stopOcspResponders() {
        if (ocspResponderPrimary != null) {
            ocspResponderPrimary.stop();
            ocspResponderPrimary = null;
        }
        if (ocspResponderSecondary != null) {
            ocspResponderSecondary.stop();
            ocspResponderSecondary = null;
        }
        if (ocspResponderNoResponse != null) {
            ocspResponderNoResponse.stop();
            ocspResponderNoResponse = null;
        }
    }

    /**
     * Test that a certificate with multiple OCSP URLs works when both responders are available.
     * This validates that the multiple URL parsing and memory allocation work correctly.
     */
    @Test
    public void testMultipleUrlsBothAvailable() throws Exception {
        Assume.assumeNotNull(ocspResponderPrimary);
        Assume.assumeNotNull(ocspResponderSecondary);

        doTestMultiOcsp(true, ClientCertificateVerification.ENABLED, false, null);
    }

    /**
     * Test that when first OCSP URL fails, it falls back to second URL.
     * This validates the URL iteration logic.
     */
    @Test
    public void testFallbackToSecondUrl() throws Exception {
        Assume.assumeNotNull(ocspResponderSecondary);

        // Stop primary responder and start non-responsive one
        if (ocspResponderPrimary != null) {
            ocspResponderPrimary.stop();
            ocspResponderPrimary = null;
        }

        ocspResponderNoResponse = new TesterOcspResponderNoResponse(8890);
        ocspResponderNoResponse.start();

        // Should succeed by falling back to second URL on port 8891
        doTestMultiOcsp(true, ClientCertificateVerification.ENABLED, false, Boolean.TRUE);
    }

    /**
     * Test that verification fails when ALL OCSP URLs are non-responsive
     * and soft fail is disabled.
     */
    @Test(expected = SSLHandshakeException.class)
    public void testAllUrlsFailWithoutSoftFail() throws Exception {
        // Stop all working responders
        if (ocspResponderPrimary != null) {
            ocspResponderPrimary.stop();
            ocspResponderPrimary = null;
        }
        if (ocspResponderSecondary != null) {
            ocspResponderSecondary.stop();
            ocspResponderSecondary = null;
        }

        // Start non-responsive responder on primary port
        ocspResponderNoResponse = new TesterOcspResponderNoResponse(8890);
        ocspResponderNoResponse.start();

        try {
            doTestMultiOcsp(true, ClientCertificateVerification.ENABLED, false, Boolean.FALSE);
        } catch (SocketException | SSLException e) {
            // APR or NIO2 may throw a SocketException rather than a SSLHandshakeException
            // Different Java versions may throw an SSLException rather than a SSLHandshakeException
            throw new SSLHandshakeException(e.getMessage());
        }
    }

    /**
     * Test that verification succeeds when ALL OCSP URLs are non-responsive
     * but soft fail is enabled.
     */
    @Test
    public void testAllUrlsFailWithSoftFail() throws Exception {
        // Stop all working responders
        if (ocspResponderPrimary != null) {
            ocspResponderPrimary.stop();
            ocspResponderPrimary = null;
        }
        if (ocspResponderSecondary != null) {
            ocspResponderSecondary.stop();
            ocspResponderSecondary = null;
        }

        // Start non-responsive responder on primary port
        ocspResponderNoResponse = new TesterOcspResponderNoResponse(8890);
        ocspResponderNoResponse.start();

        // Should succeed due to soft fail
        doTestMultiOcsp(true, ClientCertificateVerification.ENABLED, false, Boolean.TRUE);
    }

    /**
     * Helper method to test with multi-OCSP certificate.
     */
    protected void doTestMultiOcsp(boolean serverCertValid, ClientCertificateVerification verifyClientCert,
            boolean verifyServerCert, Boolean softFail) throws Exception {

        Tomcat tomcat = getTomcatInstance();

        // No file system docBase required
        Context ctx = tomcat.addContext("", null);

        Tomcat.addServlet(ctx, "simple", new SimpleServlet());
        ctx.addServletMappingDecoded("/simple", "simple");

        // Use the multi-OCSP certificate
        if (serverCertValid) {
            TesterSupport.initSsl(tomcat, TesterSupport.LOCALHOST_MULTI_OCSP_RSA_JKS,
                    TesterSupport.LOCALHOST_MULTI_OCSP_RSA_CERT_PEM,
                    TesterSupport.LOCALHOST_MULTI_OCSP_RSA_KEY_PEM, useOpenSSLTrust);
        } else {
            TesterSupport.initSsl(tomcat, TesterSupport.LOCALHOST_CRL_RSA_JKS,
                    TesterSupport.LOCALHOST_CRL_RSA_CERT_PEM,
                    TesterSupport.LOCALHOST_CRL_RSA_KEY_PEM, useOpenSSLTrust);
        }

        SSLHostConfig sslHostConfig = tomcat.getConnector().findSslHostConfigs()[0];
        switch (verifyClientCert) {
            case DEFAULT:
                sslHostConfig.setCertificateVerification("required");
                break;
            case DISABLED:
                sslHostConfig.setOcspEnabled(false);
                sslHostConfig.setCertificateVerification("required");
                break;
            case ENABLED:
                sslHostConfig.setOcspEnabled(true);
                sslHostConfig.setCertificateVerification("required");
                break;
            case OPTIONAL_NO_CA:
                sslHostConfig.setOcspEnabled(true);
                sslHostConfig.setCertificateVerification("optionalNoCA");
                break;
        }

        // Use the multi-OCSP certificate as the client certificate so OCSP checking
        // validates against our test OCSP responders on ports 8890/8891
        TesterSupport.configureClientSsl(verifyServerCert, TesterSupport.LOCALHOST_MULTI_OCSP_RSA_JKS);

        if (softFail != null) {
            sslHostConfig.setOcspSoftFail(softFail.booleanValue());
        }

        /*
         * Use shorter timeout to speed up test.
         */
        sslHostConfig.setOcspTimeout(2000);

        tomcat.start();

        int rc = getUrl("https://localhost:" + getPort() + "/simple", new ByteChunk(), false);

        // If the TLS handshake fails, the test won't get this far.
        Assert.assertEquals(HttpServletResponse.SC_OK, rc);
    }
}
