package org.asamk.signal.manager.config;

import org.asamk.signal.manager.api.ServiceEnvironment;
import org.signal.libsignal.protocol.util.Medium;
import org.whispersystems.signalservice.api.account.AccountAttributes;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.nio.charset.Charset;
import java.nio.charset.StandardCharsets;
import java.util.List;
import java.util.Locale;
import java.util.Set;
import java.util.concurrent.TimeUnit;

import okhttp3.Headers;
import okhttp3.Interceptor;
import okhttp3.Request;
import okhttp3.RequestBody;
import okhttp3.Response;
import okhttp3.ResponseBody;
import okio.Buffer;

public class ServiceConfig {
    private static final Logger logger = LoggerFactory.getLogger(ServiceConfig.class);
    private static final int BODY_LOG_LIMIT = 4096;
    private static final Set<String> SENSITIVE_HEADERS = Set.of("authorization", "x-signal-agent", "cookie");

    public static final int PREKEY_MINIMUM_COUNT = 10;
    public static final int PREKEY_BATCH_SIZE = 100;
    public static final int PREKEY_MAXIMUM_ID = Medium.MAX_VALUE;
    public static final long PREKEY_ARCHIVE_AGE = TimeUnit.DAYS.toMillis(30);
    public static final long PREKEY_STALE_AGE = TimeUnit.DAYS.toMillis(90);
    public static final long SIGNED_PREKEY_ROTATE_AGE = TimeUnit.DAYS.toMillis(2);

    public static final int MAX_ATTACHMENT_SIZE = 150 * 1024 * 1024;
    public static final long MAX_ENVELOPE_SIZE = 0;
    public static final int MAX_MESSAGE_SIZE_BYTES = 2000;
    public static final long AVATAR_DOWNLOAD_FAILSAFE_MAX_SIZE = 10 * 1024 * 1024;
    public static final boolean AUTOMATIC_NETWORK_RETRY = true;
    public static final int GROUP_MAX_SIZE = 1001;
    public static final int MAXIMUM_ONE_OFF_REQUEST_SIZE = 3;
    public static final long UNREGISTERED_LIFESPAN = TimeUnit.DAYS.toMillis(30);

    public static AccountAttributes.Capabilities getCapabilities(boolean isPrimaryDevice) {
        final var attachmentBackfill = !isPrimaryDevice;
        final var spqr = !isPrimaryDevice;
        return new AccountAttributes.Capabilities(true, true, attachmentBackfill, spqr);
    }

    public static ServiceEnvironmentConfig getServiceEnvironmentConfig(
            ServiceEnvironment serviceEnvironment,
            String userAgent
    ) {
        final Interceptor requestDomainLoggingInterceptor = chain -> {
            final var request = chain.request();
            final var url = request.url();
            final long startNs = System.nanoTime();
            logger.error(
                    "HTTP request start: method={}, scheme={}, host={}, path={}, query={}, headers={}, body={}",
                    request.method(),
                    url.scheme(),
                    url.host(),
                    url.encodedPath(),
                    url.encodedQuery(),
                    summarizeHeaders(request.headers()),
                    summarizeRequestBody(request)
            );
            try {
                final Response response = chain.proceed(request);
                final long elapsedMs = TimeUnit.NANOSECONDS.toMillis(System.nanoTime() - startNs);
                logger.error("HTTP request end: method={}, host={}, path={}, status={}, elapsedMs={}, responseHeaders={}, responseBody={}",
                        request.method(),
                        url.host(),
                        url.encodedPath(),
                        response.code(),
                        elapsedMs,
                        summarizeHeaders(response.headers()),
                        summarizeResponseBody(response));
                return response;
            } catch (Exception e) {
                final long elapsedMs = TimeUnit.NANOSECONDS.toMillis(System.nanoTime() - startNs);
                logger.error("HTTP request failed: method={}, host={}, path={}, elapsedMs={}, error={}",
                        request.method(),
                        url.host(),
                        url.encodedPath(),
                        elapsedMs,
                        e.toString());
                throw e;
            }
        };

        final Interceptor userAgentInterceptor = chain -> chain.proceed(chain.request()
                .newBuilder()
                .header("User-Agent", userAgent)
                .build());

        final var interceptors = List.of(requestDomainLoggingInterceptor, userAgentInterceptor);

        return switch (serviceEnvironment) {
            case LIVE -> LiveConfig.getServiceEnvironmentConfig(interceptors);
            case STAGING -> StagingConfig.getServiceEnvironmentConfig(interceptors);
        };
    }

    private static String summarizeHeaders(final Headers headers) {
        if (headers == null || headers.size() == 0) {
            return "{}";
        }
        final var sb = new StringBuilder("{");
        for (int i = 0; i < headers.size(); i++) {
            if (i > 0) {
                sb.append(", ");
            }
            final String name = headers.name(i);
            final String lower = name.toLowerCase(Locale.ROOT);
            final String value = SENSITIVE_HEADERS.contains(lower) ? "<redacted>" : trim(headers.value(i), 256);
            sb.append(name).append("=").append(value);
        }
        sb.append("}");
        return sb.toString();
    }

    private static String summarizeRequestBody(final Request request) {
        final RequestBody body = request.body();
        if (body == null) {
            return "<none>";
        }
        try {
            final var contentType = body.contentType();
            final var buffer = new Buffer();
            body.writeTo(buffer);
            final Charset charset = contentType != null && contentType.charset(StandardCharsets.UTF_8) != null
                    ? contentType.charset(StandardCharsets.UTF_8)
                    : StandardCharsets.UTF_8;
            final String payload = trim(buffer.readString(charset), BODY_LOG_LIMIT);
            return "contentType=" + contentType + ", size=" + body.contentLength() + ", payload=" + payload;
        } catch (Exception e) {
            return "<unavailable:" + e.getClass().getSimpleName() + ">";
        }
    }

    private static String summarizeResponseBody(final Response response) {
        final ResponseBody body = response.body();
        if (body == null) {
            return "<none>";
        }
        try {
            final var contentType = body.contentType();
            final Charset charset = contentType != null && contentType.charset(StandardCharsets.UTF_8) != null
                    ? contentType.charset(StandardCharsets.UTF_8)
                    : StandardCharsets.UTF_8;
            final var peeked = response.peekBody(BODY_LOG_LIMIT);
            final String payload = trim(peeked.source().buffer().clone().readString(charset), BODY_LOG_LIMIT);
            return "contentType=" + contentType + ", size~=" + peeked.contentLength() + ", payload=" + payload;
        } catch (Exception e) {
            return "<unavailable:" + e.getClass().getSimpleName() + ">";
        }
    }

    private static String trim(final String value, final int maxLen) {
        if (value == null) {
            return "null";
        }
        return value.length() <= maxLen ? value : value.substring(0, maxLen) + "...(truncated)";
    }
}
