package com.ourgiant.passman.util;

import org.junit.jupiter.api.Test;

import javax.net.ssl.X509TrustManager;
import java.net.http.HttpClient;
import java.security.cert.CertificateException;
import java.security.cert.X509Certificate;
import java.time.Duration;
import java.util.List;

import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertDoesNotThrow;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.mockito.Mockito.mock;

class HttpClientFactoryTest {

    @Test
    void createReturnsAClientWithTheRequestedConnectTimeout() {
        HttpClient client = HttpClientFactory.create(Duration.ofSeconds(5));

        assertEquals(Duration.ofSeconds(5), client.connectTimeout().orElseThrow());
    }

    @Test
    void mergeTrustsAChainIfAnyDelegateTrustsIt() {
        X509TrustManager rejects = rejectingTrustManager();
        X509TrustManager accepts = acceptingTrustManager();

        X509TrustManager merged = HttpClientFactory.merge(List.of(rejects, accepts));

        assertDoesNotThrow(() -> merged.checkServerTrusted(new X509Certificate[0], "RSA"));
    }

    @Test
    void mergeRejectsAChainOnlyIfEveryDelegateRejectsIt() {
        X509TrustManager merged = HttpClientFactory.merge(List.of(rejectingTrustManager(), rejectingTrustManager()));

        assertThrows(CertificateException.class,
            () -> merged.checkServerTrusted(new X509Certificate[0], "RSA"));
    }

    @Test
    void mergeCombinesAcceptedIssuersFromEveryDelegate() {
        X509Certificate issuerA = mock(X509Certificate.class);
        X509Certificate issuerB = mock(X509Certificate.class);
        X509Certificate issuerC = mock(X509Certificate.class);

        X509TrustManager merged = HttpClientFactory.merge(
            List.of(acceptingTrustManager(issuerA, issuerB), acceptingTrustManager(issuerC)));

        assertArrayEquals(new X509Certificate[]{issuerA, issuerB, issuerC}, merged.getAcceptedIssuers());
    }

    private static X509TrustManager acceptingTrustManager(X509Certificate... issuers) {
        return new X509TrustManager() {
            @Override
            public void checkClientTrusted(X509Certificate[] chain, String authType) {
            }

            @Override
            public void checkServerTrusted(X509Certificate[] chain, String authType) {
            }

            @Override
            public X509Certificate[] getAcceptedIssuers() {
                return issuers;
            }
        };
    }

    private static X509TrustManager rejectingTrustManager() {
        return new X509TrustManager() {
            @Override
            public void checkClientTrusted(X509Certificate[] chain, String authType) throws CertificateException {
                throw new CertificateException("untrusted");
            }

            @Override
            public void checkServerTrusted(X509Certificate[] chain, String authType) throws CertificateException {
                throw new CertificateException("untrusted");
            }

            @Override
            public X509Certificate[] getAcceptedIssuers() {
                return new X509Certificate[0];
            }
        };
    }
}
