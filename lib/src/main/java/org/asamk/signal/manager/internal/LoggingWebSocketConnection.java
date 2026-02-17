package org.asamk.signal.manager.internal;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.whispersystems.signalservice.api.websocket.WebSocketConnectionState;
import org.whispersystems.signalservice.internal.websocket.WebSocketConnection;
import org.whispersystems.signalservice.internal.websocket.WebSocketRequestMessage;
import org.whispersystems.signalservice.internal.websocket.WebSocketResponseMessage;
import org.whispersystems.signalservice.internal.websocket.WebsocketResponse;

import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.util.Optional;
import java.util.concurrent.TimeoutException;

import io.reactivex.rxjava3.core.Observable;
import io.reactivex.rxjava3.core.Single;
import kotlin.jvm.functions.Function1;
import okio.ByteString;

public class LoggingWebSocketConnection implements WebSocketConnection {

    private static final Logger logger = LoggerFactory.getLogger(LoggingWebSocketConnection.class);
    private static final int BODY_LOG_LIMIT = 4096;

    private final String role;
    private final String targetBaseUrl;
    private final WebSocketConnection delegate;

    public LoggingWebSocketConnection(
            final String role,
            final String targetBaseUrl,
            final WebSocketConnection delegate
    ) {
        this.role = role;
        this.targetBaseUrl = targetBaseUrl;
        this.delegate = delegate;
    }

    @Override
    public String getName() {
        return delegate.getName();
    }

    @Override
    public Observable<WebSocketConnectionState> connect() {
        logger.error("[WS:{}] connect start target={}", role, targetBaseUrl);
        return delegate.connect()
                .doOnNext(state -> logger.error("[WS:{}] state={} target={}", role, state, targetBaseUrl))
                .doOnError(error -> logger.error("[WS:{}] connect failed target={} error={}",
                        role,
                        targetBaseUrl,
                        error.toString()));
    }

    @Override
    public boolean isDead() {
        return delegate.isDead();
    }

    @Override
    public void disconnect() {
        logger.error("[WS:{}] disconnect target={}", role, targetBaseUrl);
        delegate.disconnect();
    }

    @Override
    public Single<WebsocketResponse> sendRequest(final WebSocketRequestMessage requestMessage, final long timeout)
            throws IOException {
        logger.error("[WS:{}] request start target={} verb={} path={} timeout={} headers={} body={}",
                role,
                targetBaseUrl,
                requestMessage.verb,
                requestMessage.path,
                timeout,
                requestMessage.headers,
                summarizeBody(requestMessage.body));

        return delegate.sendRequest(requestMessage, timeout)
                .doOnSuccess(response -> logger.error("[WS:{}] request end target={} verb={} path={} status={} headers={} body={}",
                        role,
                        targetBaseUrl,
                        requestMessage.verb,
                        requestMessage.path,
                        response.getStatus(),
                        response.getHeaders(),
                        trim(response.getBody(), BODY_LOG_LIMIT)))
                .doOnError(error -> logger.error("[WS:{}] request failed target={} verb={} path={} error={}",
                        role,
                        targetBaseUrl,
                        requestMessage.verb,
                        requestMessage.path,
                        error.toString()));
    }

    @Override
    public void sendKeepAlive() throws IOException {
        logger.error("[WS:{}] keepalive target={}", role, targetBaseUrl);
        delegate.sendKeepAlive();
    }

    @Override
    public Optional<WebSocketRequestMessage> readRequestIfAvailable() {
        final var request = delegate.readRequestIfAvailable();
        request.ifPresent(r -> logger.error("[WS:{}] incoming request target={} verb={} path={} headers={} body={}",
                role,
                targetBaseUrl,
                r.verb,
                r.path,
                r.headers,
                summarizeBody(r.body)));
        return request;
    }

    @Override
    public WebSocketRequestMessage readRequest(final long timeout) throws TimeoutException, IOException {
        final var request = delegate.readRequest(timeout);
        logger.error("[WS:{}] incoming request wait target={} timeout={} verb={} path={} headers={} body={}",
                role,
                targetBaseUrl,
                timeout,
                request.verb,
                request.path,
                request.headers,
                summarizeBody(request.body));
        return request;
    }

    @Override
    public void sendResponse(final WebSocketResponseMessage responseMessage) throws IOException {
        logger.error("[WS:{}] send response target={} id={} status={} message={}",
                role,
                targetBaseUrl,
                responseMessage.id,
                responseMessage.status,
                trim(responseMessage.message, BODY_LOG_LIMIT));
        delegate.sendResponse(responseMessage);
    }

    @Override
    public <T> Object runWithChatConnection(
            final Function1<? super org.signal.libsignal.net.ChatConnection, ? extends T> action,
            final kotlin.coroutines.Continuation<? super T> continuation
    ) {
        return delegate.runWithChatConnection(action, continuation);
    }

    private static String summarizeBody(final ByteString body) {
        if (body == null) {
            return "<none>";
        }
        try {
            final var payload = trim(body.string(StandardCharsets.UTF_8), BODY_LOG_LIMIT);
            return "size=" + body.size() + ", payload=" + payload;
        } catch (Exception e) {
            return "size=" + body.size() + ", payload=<binary>";
        }
    }

    private static String trim(final String value, final int maxLen) {
        if (value == null) {
            return "null";
        }
        return value.length() <= maxLen ? value : value.substring(0, maxLen) + "...(truncated)";
    }
}
