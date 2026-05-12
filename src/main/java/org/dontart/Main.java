package org.dontart;

import java.io.*;
import java.net.*;
import java.nio.charset.StandardCharsets;
import java.time.LocalTime;
import java.util.*;
import java.util.concurrent.atomic.AtomicInteger;

public class Main {
    // Настройки
    private static final int PORT = 26288;
    private static final String BIND_ADDRESS = "0.0.0.0";
    private static final String PROXY_USER = "cheski";
    private static final String PROXY_PASS = "cheski6";
    private static final int BUFFER_SIZE = 8192;

    private static final AtomicInteger activeConnections = new AtomicInteger(0);
    private static final String AUTH_TOKEN = Base64.getEncoder()
            .encodeToString((PROXY_USER + ":" + PROXY_PASS).getBytes());
    private static final String EXPECTED_AUTH = "Basic " + AUTH_TOKEN;

    public static void main(String[] args) throws IOException {
        try (ServerSocket server = new ServerSocket()) {
            server.bind(new InetSocketAddress(BIND_ADDRESS, PORT));
            server.setReuseAddress(true);

            log("Proxy on " + BIND_ADDRESS + ":" + PORT);
            log("Login: " + PROXY_USER + " / Pass: " + PROXY_PASS);

            while (true) {
                Socket client = server.accept();
                Thread.startVirtualThread(() -> handle(client));
            }
        }
    }

    static void handle(Socket client) {
        activeConnections.incrementAndGet();
        String clientIp = client.getInetAddress().getHostAddress();

        try {
            client.setTcpNoDelay(true);
            InputStream in = new BufferedInputStream(client.getInputStream(), BUFFER_SIZE);
            OutputStream out = new BufferedOutputStream(client.getOutputStream(), BUFFER_SIZE);

            // Читаем первую строку
            String firstLine = readHttpLine(in);
            if (firstLine == null || firstLine.isEmpty()) return;

            log("[" + clientIp + "] " + firstLine);

            // Читаем ВСЕ заголовки в список
            List<String> headerLines = new ArrayList<>();
            String line;
            boolean authed = false;

            while ((line = readHttpLine(in)) != null && !line.isEmpty()) {
                headerLines.add(line);
                if (line.toLowerCase().startsWith("proxy-authorization:")) {
                    String authValue = line.substring(21).trim();
                    if (authValue.equals(EXPECTED_AUTH)) {
                        authed = true;
                    }
                }
            }

            // Проверяем авторизацию
            if (!authed) {
                out.write("HTTP/1.1 407 Proxy Authentication Required\r\nProxy-Authenticate: Basic realm=\"proxy\"\r\nContent-Length: 0\r\n\r\n".getBytes());
                out.flush();
                log("[" + clientIp + "] Auth failed");
                return;
            }

            // Парсим хост и порт
            String host = null;
            int port = firstLine.startsWith("CONNECT") ? 443 : 80;

            for (String h : headerLines) {
                if (h.toLowerCase().startsWith("host:")) {
                    String hostPart = h.substring(5).trim();
                    if (hostPart.contains(":")) {
                        String[] parts = hostPart.split(":", 2);
                        host = parts[0];
                        port = Integer.parseInt(parts[1]);
                    } else {
                        host = hostPart;
                    }
                }
            }

            if (host == null) {
                out.write("HTTP/1.1 400 Bad Request\r\nContent-Length: 0\r\n\r\n".getBytes());
                out.flush();
                return;
            }

            // Маршрутизируем
            if (firstLine.startsWith("CONNECT")) {
                handleConnect(client, in, out, host, port, clientIp);
            } else {
                handleHttp(client, in, out, firstLine, headerLines, host, port, clientIp);
            }

        } catch (IOException e) {
            log("[" + clientIp + "] Error: " + e.getMessage());
        } finally {
            activeConnections.decrementAndGet();
            try { client.close(); } catch (IOException ignored) {}
        }
    }

    static void handleConnect(Socket client, InputStream clientIn, OutputStream clientOut,
                              String host, int port, String clientIp) {
        log("[" + clientIp + "] CONNECT → " + host + ":" + port);

        try (Socket server = new Socket(host, port)) {
            server.setTcpNoDelay(true);

            clientOut.write("HTTP/1.1 200 Connection Established\r\n\r\n".getBytes());
            clientOut.flush();

            InputStream serverIn = new BufferedInputStream(server.getInputStream(), BUFFER_SIZE);
            OutputStream serverOut = new BufferedOutputStream(server.getOutputStream(), BUFFER_SIZE);

            Thread c2s = Thread.startVirtualThread(() -> transfer(clientIn, serverOut));
            Thread s2c = Thread.startVirtualThread(() -> transfer(serverIn, clientOut));

            c2s.join();
        } catch (Exception e) {
            log("[" + clientIp + "] CONNECT failed: " + e.getMessage());
        }
    }

    static void handleHttp(Socket client, InputStream clientIn, OutputStream clientOut,
                           String firstLine, List<String> headers,
                           String host, int port, String clientIp) throws IOException {
        log("[" + clientIp + "] HTTP → " + host + ":" + port);

        // Собираем запрос
        StringBuilder request = new StringBuilder();
        request.append(firstLine).append("\r\n");

        long contentLength = 0;
        for (String h : headers) {
            // Пропускаем прокси-авторизацию при отправке на целевой сервер
            if (h.toLowerCase().startsWith("proxy-authorization:")) continue;
            request.append(h).append("\r\n");

            if (h.toLowerCase().startsWith("content-length:")) {
                contentLength = Long.parseLong(h.substring(15).trim());
            }
        }
        request.append("\r\n");

        try (Socket server = new Socket(host, port)) {
            server.setTcpNoDelay(true);
            OutputStream serverOut = new BufferedOutputStream(server.getOutputStream(), BUFFER_SIZE);
            InputStream serverIn = new BufferedInputStream(server.getInputStream(), BUFFER_SIZE);

            serverOut.write(request.toString().getBytes());

            // Тело запроса
            if (contentLength > 0) {
                byte[] buf = new byte[BUFFER_SIZE];
                long remaining = contentLength;
                while (remaining > 0) {
                    int n = clientIn.read(buf, 0, (int) Math.min(remaining, BUFFER_SIZE));
                    if (n == -1) break;
                    serverOut.write(buf, 0, n);
                    remaining -= n;
                }
            }

            serverOut.flush();
            transfer(serverIn, clientOut);
            clientOut.flush();
        } catch (IOException e) {
            log("[" + clientIp + "] HTTP failed: " + e.getMessage());
        }
    }

    private static void transfer(InputStream in, OutputStream out) {
        byte[] buf = new byte[BUFFER_SIZE];
        try {
            int n;
            while ((n = in.read(buf)) != -1) {
                out.write(buf, 0, n);
                out.flush();
            }
        } catch (IOException ignored) {
        } finally {
            try { in.close(); } catch (IOException ignored) {}
            try { out.close(); } catch (IOException ignored) {}
        }
    }

    private static String readHttpLine(InputStream in) throws IOException {
        ByteArrayOutputStream buf = new ByteArrayOutputStream();
        int prev = -1;
        int ch;
        while ((ch = in.read()) != -1) {
            if (prev == '\r' && ch == '\n') {
                buf.write('\r');
                buf.write('\n');
                break;
            }
            if (prev != -1) buf.write(prev);
            prev = ch;
        }
        if (ch == -1 && buf.size() == 0) return null;
        if (ch == -1 && prev != -1) buf.write(prev);
        return buf.toString(StandardCharsets.UTF_8).trim();
    }

    private static void log(String msg) {
        System.out.printf("[%s] [%d] %s%n",
                LocalTime.now().withNano(0),
                activeConnections.get(),
                msg);
    }
}