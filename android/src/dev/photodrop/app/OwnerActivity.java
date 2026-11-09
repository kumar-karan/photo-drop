package dev.photodrop.app;

import android.app.Activity;
import android.content.SharedPreferences;
import android.net.Uri;
import android.os.Bundle;
import android.os.Handler;
import android.os.Looper;
import android.view.View;
import android.webkit.WebChromeClient;
import android.webkit.WebResourceError;
import android.webkit.WebResourceRequest;
import android.webkit.WebResourceResponse;
import android.webkit.WebSettings;
import android.webkit.WebView;
import android.webkit.WebViewClient;
import android.widget.Button;
import android.widget.TextView;

import java.io.BufferedReader;
import java.io.InputStreamReader;
import java.net.HttpURLConnection;
import java.net.URL;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;

/**
 * The owner dashboard, inside the app.
 *
 * It loads the local server over loopback rather than the public tunnel, so it
 * keeps working on a plane, on a bad hotspot, or after the trycloudflare URL
 * has been re-minted. It also always uses the owner token the app minted,
 * which is the token pd-control.sh writes into the server's env — the mismatch
 * that used to make the browser dashboard return 404.
 */
public class OwnerActivity extends Activity {

    static final int PORT = 8080;
    static final String PREFS = "photodrop";
    static final String K_OWNER = "owner_token";

    final ExecutorService exec = Executors.newSingleThreadExecutor();
    final Handler handler = new Handler(Looper.getMainLooper());

    WebView web;
    View offline;
    TextView status;
    Button refresh;

    String ownerToken = "";
    boolean loadedOnce = false;

    @Override
    protected void onCreate(Bundle savedInstanceState) {
        super.onCreate(savedInstanceState);
        setContentView(R.layout.activity_owner);

        web = findViewById(R.id.ownerWeb);
        offline = findViewById(R.id.ownerOffline);
        status = findViewById(R.id.tvOwnerStatus);
        refresh = findViewById(R.id.btnOwnerRefresh);

        SharedPreferences prefs = getSharedPreferences(PREFS, MODE_PRIVATE);
        ownerToken = prefs.getString(K_OWNER, "");

        findViewById(R.id.btnOwnerBack).setOnClickListener(v -> finish());
        findViewById(R.id.btnOwnerRetry).setOnClickListener(v -> load());
        refresh.setOnClickListener(v -> load());

        WebSettings settings = web.getSettings();
        settings.setJavaScriptEnabled(true);
        settings.setDomStorageEnabled(true);
        settings.setAllowFileAccess(false);
        settings.setAllowContentAccess(false);
        settings.setSupportZoom(false);
        settings.setBuiltInZoomControls(false);
        settings.setDisplayZoomControls(false);
        settings.setCacheMode(WebSettings.LOAD_NO_CACHE);
        settings.setUserAgentString(settings.getUserAgentString() + " PhotoDropApp/1.6");

        web.setBackgroundColor(0xFFF9F9FF);
        web.setWebViewClient(new WebViewClient() {
            @Override
            public void onPageFinished(WebView view, String url) {
                loadedOnce = true;
                // A 404 page also "finishes"; do not label that Live.
                if (offline.getVisibility() != View.VISIBLE) status.setText("Live");
            }

            @Override
            public void onReceivedError(WebView view, WebResourceRequest request,
                                        WebResourceError error) {
                if (request.isForMainFrame()) {
                    showOffline("Could not reach the local server.");
                }
            }

            @Override
            public void onReceivedHttpError(WebView view, WebResourceRequest request,
                                            WebResourceResponse response) {
                if (request.isForMainFrame() && response.getStatusCode() == 404) {
                    showOffline("The server is running, but it rejected this owner token. "
                            + "Stop and Start Photo Drop once to resync, then tap Retry.");
                }
            }
        });
        web.setWebChromeClient(new WebChromeClient());

        load();
    }

    void load() {
        if (ownerToken.isEmpty()) {
            showOffline("No owner token yet. Start Photo Drop once from the main screen.");
            return;
        }
        status.setText("Connecting…");
        refresh.setEnabled(false);
        exec.execute(() -> {
            boolean up = healthOk();
            handler.post(() -> {
                refresh.setEnabled(true);
                if (!up) {
                    showOffline("Start Photo Drop from the main screen, then tap Retry.");
                    return;
                }
                offline.setVisibility(View.GONE);
                web.setVisibility(View.VISIBLE);
                String url = "http://127.0.0.1:" + PORT + "/owner/" + Uri.encode(ownerToken);
                web.loadUrl(url);
            });
        });
    }

    boolean healthOk() {
        HttpURLConnection conn = null;
        try {
            conn = (HttpURLConnection) new URL("http://127.0.0.1:" + PORT + "/healthz").openConnection();
            conn.setConnectTimeout(1500);
            conn.setReadTimeout(2000);
            conn.setRequestMethod("GET");
            if (conn.getResponseCode() != 200) return false;
            BufferedReader reader = new BufferedReader(new InputStreamReader(conn.getInputStream()));
            StringBuilder body = new StringBuilder();
            String line;
            while ((line = reader.readLine()) != null) body.append(line);
            reader.close();
            return body.toString().contains("\"ok\":true")
                    || body.toString().contains("\"ok\": true");
        } catch (Exception e) {
            return false;
        } finally {
            if (conn != null) conn.disconnect();
        }
    }

    void showOffline(String message) {
        status.setText("Offline");
        web.setVisibility(View.GONE);
        offline.setVisibility(View.VISIBLE);
        TextView detail = findViewById(R.id.tvOwnerOfflineBody);
        detail.setText(message);
    }

    @Override
    public void onBackPressed() {
        if (web != null && web.canGoBack()) {
            web.goBack();
        } else {
            super.onBackPressed();
        }
    }

    @Override
    protected void onResume() {
        super.onResume();
        if (loadedOnce && web.getVisibility() == View.VISIBLE) {
            // Pick up sessions that arrived while the dashboard was in the
            // background. The page also polls while it is visible.
            web.reload();
        }
    }

    @Override
    protected void onDestroy() {
        exec.shutdownNow();
        if (web != null) {
            web.destroy();
            web = null;
        }
        super.onDestroy();
    }
}
