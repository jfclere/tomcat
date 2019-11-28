package org.apache.catalina.tribes.membership.cloud;

import javax.net.ssl.TrustManager;
import javax.net.ssl.X509TrustManager;
import java.security.cert.CertificateException;
import java.security.cert.X509Certificate;

public class TrustSelfSignedX509TrustManager implements X509TrustManager {
    private X509TrustManager delegate;

    public TrustSelfSignedX509TrustManager(TrustManager delegate) {
        this.delegate = (X509TrustManager) delegate;
    }

    @Override
    public void checkClientTrusted(X509Certificate[] chain, String authType) throws CertificateException {
        delegate.checkClientTrusted(chain, authType);
    }

    @Override
    public void checkServerTrusted(X509Certificate[] chain, String authType) throws CertificateException {
        if (isSelfSigned(chain)) {
            return;
        }
        delegate.checkServerTrusted(chain, authType);
    }

    private boolean isSelfSigned(X509Certificate[] chain) {
        for (int j = 0; j < chain.length; j++) {
            System.out.println("getIssuerDN(): " + chain[j].getIssuerDN() + " getSubjectDN(): " + chain[j].getSubjectDN());
        }
        System.out.println("chain: " + chain.length);
        return chain.length == 1;
    }

    @Override
    public X509Certificate[] getAcceptedIssuers() {
        return delegate.getAcceptedIssuers();
    }

}
