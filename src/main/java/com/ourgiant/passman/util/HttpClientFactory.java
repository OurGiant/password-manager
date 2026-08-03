package com.ourgiant.passman.util;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import javax.net.ssl.SSLContext;
import javax.net.ssl.TrustManager;
import javax.net.ssl.TrustManagerFactory;
import javax.net.ssl.X509TrustManager;
import java.net.http.HttpClient;
import java.security.KeyStore;
import java.security.cert.CertificateException;
import java.security.cert.X509Certificate;
import java.time.Duration;
import java.util.ArrayList;
import java.util.List;
import java.util.Locale;

/**
 * Builds {@link HttpClient}s for the app's one outbound HTTPS call (the update check). On
 * Windows, trusts both the JDK's bundled cacerts and the OS certificate store — jpackage
 * bundles its own JRE with its own cacerts, completely separate from the Windows store, so a
 * machine that's required to go through a TLS-inspecting corporate proxy (custom root/
 * intermediate CA installed into Windows via GPO, same store the browser already trusts) fails
 * outbound HTTPS with a PKIX/SSLHandshakeException the JDK's default trust manager alone can
 * never satisfy. Ported from kiro-control-panel/doc-scrubber's same fix.
 */
public final class HttpClientFactory {
    private static final Logger logger = LoggerFactory.getLogger(HttpClientFactory.class);

    private HttpClientFactory() {
    }

    public static HttpClient create(Duration connectTimeout) {
        HttpClient.Builder builder = HttpClient.newBuilder().connectTimeout(connectTimeout);
        SSLContext sslContext = buildWindowsTrustedSslContext();
        if (sslContext != null) {
            builder.sslContext(sslContext);
        }
        return builder.build();
    }

    private static boolean isWindows() {
        return System.getProperty("os.name", "").toLowerCase(Locale.ROOT).contains("win");
    }

    private static SSLContext buildWindowsTrustedSslContext() {
        if (!isWindows()) {
            return null;
        }
        try {
            List<X509TrustManager> delegates = new ArrayList<>();
            delegates.add(x509TrustManagerFor(null));
            delegates.add(x509TrustManagerFor(windowsRootKeyStore()));

            SSLContext context = SSLContext.getInstance("TLS");
            context.init(null, new TrustManager[]{merge(delegates)}, null);
            return context;
        } catch (Exception e) {
            logger.warn("Could not build a Windows-trust-store-aware SSLContext; "
                + "falling back to the JDK's bundled cacerts only", e);
            return null;
        }
    }

    private static KeyStore windowsRootKeyStore() throws Exception {
        // The trusted-roots store Windows/the browser already use -- backed by the
        // SunMSCAPI provider, not a file this app ships or manages.
        KeyStore keyStore = KeyStore.getInstance("Windows-ROOT");
        keyStore.load(null, null);
        return keyStore;
    }

    /** @param keyStore null selects the JDK's own default cacerts. */
    private static X509TrustManager x509TrustManagerFor(KeyStore keyStore) throws Exception {
        TrustManagerFactory tmf = TrustManagerFactory.getInstance(TrustManagerFactory.getDefaultAlgorithm());
        tmf.init(keyStore);
        for (TrustManager tm : tmf.getTrustManagers()) {
            if (tm instanceof X509TrustManager x509) {
                return x509;
            }
        }
        throw new IllegalStateException("TrustManagerFactory produced no X509TrustManager");
    }

    /** Package-private, for tests: trusts a chain if ANY delegate trusts it. */
    static X509TrustManager merge(List<X509TrustManager> delegates) {
        return new X509TrustManager() {
            @Override
            public void checkClientTrusted(X509Certificate[] chain, String authType) throws CertificateException {
                delegates.get(0).checkClientTrusted(chain, authType);
            }

            @Override
            public void checkServerTrusted(X509Certificate[] chain, String authType) throws CertificateException {
                CertificateException last = null;
                for (X509TrustManager delegate : delegates) {
                    try {
                        delegate.checkServerTrusted(chain, authType);
                        return;
                    } catch (CertificateException e) {
                        last = e;
                    }
                }
                throw last;
            }

            @Override
            public X509Certificate[] getAcceptedIssuers() {
                List<X509Certificate> issuers = new ArrayList<>();
                for (X509TrustManager delegate : delegates) {
                    issuers.addAll(List.of(delegate.getAcceptedIssuers()));
                }
                return issuers.toArray(new X509Certificate[0]);
            }
        };
    }
}
