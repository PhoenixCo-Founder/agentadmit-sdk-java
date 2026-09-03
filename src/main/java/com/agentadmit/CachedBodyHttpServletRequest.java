package com.agentadmit;

import jakarta.servlet.ReadListener;
import jakarta.servlet.ServletInputStream;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletRequestWrapper;

import java.io.BufferedReader;
import java.io.ByteArrayInputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.InputStreamReader;
import java.nio.charset.Charset;
import java.nio.charset.StandardCharsets;

/**
 * Request wrapper that reads the body ONCE, keeps the raw bytes, and replays
 * them to everything downstream.
 *
 * <p>Confirm-each-time (1.11.0) needs the raw body twice: the filter digests
 * it for the verify call, and your controller still has to be able to read it.
 * A servlet body is a one-shot stream, so the filter wraps the request in this
 * before touching it and passes the wrapper down the chain.
 */
class CachedBodyHttpServletRequest extends HttpServletRequestWrapper {

    private final byte[] body;

    /**
     * Drain and cache the request body.
     *
     * @param request the request to wrap
     * @throws IOException if the body cannot be read
     */
    CachedBodyHttpServletRequest(HttpServletRequest request) throws IOException {
        super(request);
        try (InputStream in = request.getInputStream()) {
            this.body = in == null ? new byte[0] : in.readAllBytes();
        }
    }

    /**
     * The raw body bytes exactly as they arrived — what the digest commits to.
     *
     * @return the cached body (never {@code null}; empty for a bodyless request)
     */
    byte[] cachedBody() {
        return body;
    }

    /** {@inheritDoc} */
    @Override
    public ServletInputStream getInputStream() {
        ByteArrayInputStream replay = new ByteArrayInputStream(body);
        return new ServletInputStream() {
            @Override public boolean isFinished() { return replay.available() == 0; }
            @Override public boolean isReady() { return true; }
            @Override public void setReadListener(ReadListener readListener) { /* blocking replay only */ }
            @Override public int read() { return replay.read(); }
            @Override public int read(byte[] b, int off, int len) { return replay.read(b, off, len); }
            @Override public int available() { return replay.available(); }
        };
    }

    /** {@inheritDoc} */
    @Override
    public BufferedReader getReader() {
        String encoding = getCharacterEncoding();
        Charset charset = StandardCharsets.UTF_8;
        if (encoding != null) {
            try {
                charset = Charset.forName(encoding);
            } catch (RuntimeException e) {
                charset = StandardCharsets.UTF_8;
            }
        }
        return new BufferedReader(new InputStreamReader(new ByteArrayInputStream(body), charset));
    }
}
