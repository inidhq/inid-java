package co.inid;

import java.io.IOException;
import java.net.URI;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import java.time.Duration;
import java.util.Map;

/**
 * How the SDK talks to InID. The default uses java.net.http; pass your own to go through a
 * proxy, add metrics, or fake InID in tests. An IOException means InID couldn't be reached.
 */
@FunctionalInterface
public interface InIDHttp {
    record Request(String method, String url, Map<String, String> headers, String body, Duration timeout) {
    }

    record Response(int status, String body) {
        public boolean ok() {
            return status >= 200 && status < 300;
        }
    }

    Response send(Request request) throws IOException;

    static InIDHttp jdk() {
        return jdk(HttpClient.newBuilder().connectTimeout(Duration.ofSeconds(10)).build());
    }

    static InIDHttp jdk(HttpClient client) {
        return request -> {
            HttpRequest.Builder builder = HttpRequest.newBuilder(URI.create(request.url()))
                    .timeout(request.timeout() != null ? request.timeout() : Duration.ofSeconds(15))
                    .method(request.method(), request.body() == null
                            ? HttpRequest.BodyPublishers.noBody()
                            : HttpRequest.BodyPublishers.ofString(request.body()));
            request.headers().forEach(builder::header);
            try {
                HttpResponse<String> res = client.send(builder.build(), HttpResponse.BodyHandlers.ofString());
                return new Response(res.statusCode(), res.body());
            } catch (InterruptedException e) {
                Thread.currentThread().interrupt();
                throw new IOException("interrupted", e);
            }
        };
    }
}
