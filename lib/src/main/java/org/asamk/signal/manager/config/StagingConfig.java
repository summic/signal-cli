package org.asamk.signal.manager.config;

import org.signal.libsignal.net.Network;
import org.signal.libsignal.protocol.InvalidKeyException;
import org.signal.libsignal.protocol.ecc.ECPublicKey;
import org.whispersystems.signalservice.api.push.TrustStore;
import org.whispersystems.signalservice.internal.configuration.HttpProxy;
import org.whispersystems.signalservice.internal.configuration.SignalCdnUrl;
import org.whispersystems.signalservice.internal.configuration.SignalCdsiUrl;
import org.whispersystems.signalservice.internal.configuration.SignalProxy;
import org.whispersystems.signalservice.internal.configuration.SignalServiceConfiguration;
import org.whispersystems.signalservice.internal.configuration.SignalServiceUrl;
import org.whispersystems.signalservice.internal.configuration.SignalStorageUrl;
import org.whispersystems.signalservice.internal.configuration.SignalSvr2Url;

import java.util.Base64;
import java.util.List;
import java.util.Map;
import java.util.Optional;

import okhttp3.Dns;
import okhttp3.Interceptor;

import static org.asamk.signal.manager.api.ServiceEnvironment.STAGING;

class StagingConfig {

    // Self-hosted staging (deploy/nginx/staging.conf):
    // - chat-staging.beforeve.com
    // - cdn-staging.beforeve.com
    // - storage-staging.beforeve.com
    //
    // Unidentified delivery trust root is generated via:
    //   java -Dsecrets.bundle.filename=... -cp ... WhisperServerService certificate --ca
    // and must match the CA that signs `unidentifiedDelivery.certificate` in signal-server config.
    private static final byte[] UNIDENTIFIED_SENDER_TRUST_ROOT = Base64.getDecoder()
            .decode("BRSe+aurx8RvqVKsR6Eygr5WIVRzd/4jBdwLrnviY1QJ");
    private static final byte[] UNIDENTIFIED_SENDER_TRUST_ROOT2 = Base64.getDecoder()
            .decode("BRSe+aurx8RvqVKsR6Eygr5WIVRzd/4jBdwLrnviY1QJ");
    private static final String CDSI_MRENCLAVE = "0f6fd79cdfdaa5b2e6337f534d3baf999318b0c462a7ac1f41297a3e4b424a57";

    private static final String URL = "https://chat-staging.beforeve.com";
    private static final String CDN_URL = "https://cdn-staging.beforeve.com";
    private static final String CDN2_URL = "https://cdn-staging.beforeve.com";
    private static final String CDN3_URL = "https://cdn-staging.beforeve.com";
    private static final String STORAGE_URL = "https://storage-staging.beforeve.com";

    // Self-hosted stack does not include CDSI/SVR2 services. These URLs must not point at signal.org.
    // Calls will fail if those features are used.
    private static final String SIGNAL_CDSI_URL = "https://chat-staging.beforeve.com";
    private static final String SIGNAL_SVR2_URL = "https://chat-staging.beforeve.com";
    private static final TrustStore TRUST_STORE = new WhisperTrustStore();

    private static final Optional<Dns> dns = Optional.empty();
    private static final Optional<SignalProxy> proxy = Optional.empty();
    private static final Optional<HttpProxy> systemProxy = Optional.empty();

    // `zkConfig.serverPublic` from deploy/config/staging/signal-server.yml
    private static final String SERVER_PUBLIC_PARAMS_BASE64 =
            "AAweBMDqxprwsJWHAuuEsz+LhWGFt5Jxrwh2MFsG2g9tQCY0o/D07Z954XphLIXNS1LqN+1RYRQwaCTfrYtt+XWA1oEvy69mOx/9GrZ6Bvq/D/TodNNpDWeC+dV/NKDxC25wWiBpWWZWyuymq1PAVflM81KVALZoX16Ou4gctZIlrjC5tL3Va7wYChorBCszy2VQ6AbOnTvnK24xmavOJnjEQQL/h2VTIuEchhu3NkkeIo2moX67hIoXEN+VFhMqXhSEcJy6wsW+URfE5d6ugEYJyzS9ZP8RICdxw78cWJ9dMuQ09mcK0M9ykVCc8gQA0D1aj7FC5Lc3FP0v0FjCd20Exptoa6sGZ0EzHOP3aa0Qv5PravrDgmmUILSVsZPNe07MoiNGTKattNszmYvHs2LiGLJ8qYhVCRq1VLzgu4oglHXHIGhvh57+QQRV/f82rxmc/Q9xzNAus7e8lcUfGVPOzBacbiVCuSjvVH9j2m6tm50DdO3iTBcyCjdCWkeGEkq0uvfMc7Lu2/29MSMQw8DB9jy9BrLY6dEDGESxqx8V6u/53XiJS0LFsuEN9ygJfwYhdD0kSMv4+L2UnjflPh8I243XXmiI1hTGYRsVVGkCMKrITkrKxQKpYuBkN3NaP6rjFjEpYnVvcZXbxehArC6kiaSvvOLwTwaySe+a3JlydHCScY3KoW6qmC3xfMLs3eHChi5jBolCnDx2pWe0DSsywh+dnZpQk3+U3etBDsgw6a6P16Wd0XxgsajIpPZ7F9LlZdaW+6KkkQzRQZQud3kk1aD3sB3OeG+fXEJ6X4VV4qtRzX0XMBrAxAqHuzlCd0J0ULQ9PuyvLOfLu4LWmg+wMrt8V7K6SBaerb6yJyKyCtnxANgggihCOdNey7leaA==";

    // This self-host stack only provides one set of zk public params. Use it for all libsignal zk ops.
    private static final byte[] zkGroupServerPublicParams = Base64.getDecoder().decode(SERVER_PUBLIC_PARAMS_BASE64);
    private static final byte[] genericServerPublicParams = Base64.getDecoder().decode(SERVER_PUBLIC_PARAMS_BASE64);
    private static final byte[] backupServerPublicParams = Base64.getDecoder().decode(SERVER_PUBLIC_PARAMS_BASE64);

    private static final Network.Environment LIBSIGNAL_NET_ENV = Network.Environment.STAGING;

    static SignalServiceConfiguration createDefaultServiceConfiguration(
            final List<Interceptor> interceptors
    ) {
        return new SignalServiceConfiguration(new SignalServiceUrl[]{new SignalServiceUrl(URL, TRUST_STORE)},
                Map.of(0,
                        new SignalCdnUrl[]{new SignalCdnUrl(CDN_URL, TRUST_STORE)},
                        2,
                        new SignalCdnUrl[]{new SignalCdnUrl(CDN2_URL, TRUST_STORE)},
                        3,
                        new SignalCdnUrl[]{new SignalCdnUrl(CDN3_URL, TRUST_STORE)}),
                new SignalStorageUrl[]{new SignalStorageUrl(STORAGE_URL, TRUST_STORE)},
                new SignalCdsiUrl[]{new SignalCdsiUrl(SIGNAL_CDSI_URL, TRUST_STORE)},
                new SignalSvr2Url[]{new SignalSvr2Url(SIGNAL_SVR2_URL, TRUST_STORE, null, null)},
                interceptors,
                dns,
                proxy,
                systemProxy,
                zkGroupServerPublicParams,
                genericServerPublicParams,
                backupServerPublicParams,
                false);
    }

    static List<ECPublicKey> getUnidentifiedSenderTrustRoots() {
        try {
            return List.of(new ECPublicKey(UNIDENTIFIED_SENDER_TRUST_ROOT),
                    new ECPublicKey(UNIDENTIFIED_SENDER_TRUST_ROOT2));
        } catch (InvalidKeyException e) {
            throw new AssertionError(e);
        }
    }

    static ServiceEnvironmentConfig getServiceEnvironmentConfig(List<Interceptor> interceptors) {
        return new ServiceEnvironmentConfig(STAGING,
                LIBSIGNAL_NET_ENV,
                createDefaultServiceConfiguration(interceptors),
                getUnidentifiedSenderTrustRoots(),
                CDSI_MRENCLAVE,
                List.of());
    }

    private StagingConfig() {
    }
}
