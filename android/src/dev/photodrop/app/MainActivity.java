package dev.photodrop.app;

import android.app.Activity;
import android.app.AlertDialog;
import android.content.ClipData;
import android.content.ClipboardManager;
import android.content.Context;
import android.content.Intent;
import android.content.SharedPreferences;
import android.content.pm.PackageManager;
import android.graphics.Bitmap;
import android.graphics.Insets;
import android.net.Uri;
import android.os.Build;
import android.os.Bundle;
import android.os.Handler;
import android.os.Looper;
import android.provider.Settings;
import android.util.Log;
import android.view.MotionEvent;
import android.view.View;
import android.view.WindowInsets;
import android.view.animation.PathInterpolator;
import android.widget.Button;
import android.widget.ImageView;
import android.widget.LinearLayout;
import android.widget.TextView;
import android.widget.Toast;

import com.google.zxing.BarcodeFormat;
import com.google.zxing.WriterException;
import com.google.zxing.common.BitMatrix;
import com.google.zxing.qrcode.QRCodeWriter;

import java.io.BufferedReader;
import java.io.File;
import java.io.FileReader;
import java.net.HttpURLConnection;
import java.net.Inet4Address;
import java.net.InetAddress;
import java.net.NetworkInterface;
import java.net.URL;
import java.security.SecureRandom;
import java.util.Collections;
import java.util.List;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;

/**
 * Main activity implementing the B+C "Handoff" architecture.
 *
 * One screen, two jobs at two moments:
 * 1. Flip the switch (OrbView in the Stage)
 * 2. Become the card you hand over (184dp QR Handoff Card + Bottom Sheet controls)
 */
public class MainActivity extends Activity {
    static final int PORT = 8080;
    static final String PREFS = "photodrop";
    static final String K_DROP = "drop_token";
    static final String K_OWNER = "owner_token";

    static final PathInterpolator EASE = new PathInterpolator(0.2f, 0f, 0f, 1f);

    public enum AppState {
        STOPPED,
        STARTING,
        ONLINE_LOCAL,
        ONLINE_TUNNEL,
        STORAGE_LOW,
        TERMUX_ERROR
    }

    final ExecutorService exec = Executors.newSingleThreadExecutor();
    final Handler handler = new Handler(Looper.getMainLooper());
    Runnable poller;
    Runnable copyReset;

    // UI Views
    StatusStripView statusStrip;
    View orbStage;
    OrbView orbView;
    TextView tvOrbCaption;

    View handoffCard;
    TextView tvDockedBadge;
    TextView tvDropDomain;
    TextView tvDropUrl;
    ImageView imgQr;
    TextView tvDropHint;

    View alertCard;
    TextView tvAlertDesc;

    View permCard;
    Button btnFixPerm;

    View sheet;
    View liveControls;
    TextView tvSheetUrl;
    Button btnFlipHost;
    Button btnCopy;

    TextView tvFree;
    StorageBarView storageBar;
    TextView tvSessions;

    View liveStopSection;
    Button btnStop;
    Button btnOwner;

    // State variables
    String dropToken = "";
    String ownerToken = "";
    String publicUrl = "";
    String lanIp = "";
    boolean preferTunnel = true;

    AppState state = AppState.STOPPED;
    Health lastHealth = Health.down();
    boolean starting = false;
    String qrForUrl = "";

    @Override
    protected void onCreate(Bundle savedInstanceState) {
        super.onCreate(savedInstanceState);
        setContentView(R.layout.activity_main);

        statusStrip = findViewById(R.id.statusStrip);
        orbStage = findViewById(R.id.orbStage);
        orbView = findViewById(R.id.orbView);
        tvOrbCaption = findViewById(R.id.tvOrbCaption);

        handoffCard = findViewById(R.id.handoffCard);
        tvDockedBadge = findViewById(R.id.tvDockedBadge);
        tvDropDomain = findViewById(R.id.tvDropDomain);
        tvDropUrl = findViewById(R.id.tvDropUrl);
        imgQr = findViewById(R.id.imgQr);
        tvDropHint = findViewById(R.id.tvDropHint);

        alertCard = findViewById(R.id.alertCard);
        tvAlertDesc = findViewById(R.id.tvAlertDesc);

        permCard = findViewById(R.id.permCard);
        btnFixPerm = findViewById(R.id.btnFixPerm);

        sheet = findViewById(R.id.sheet);
        liveControls = findViewById(R.id.liveControls);
        tvSheetUrl = findViewById(R.id.tvSheetUrl);
        btnFlipHost = findViewById(R.id.btnFlipHost);
        btnCopy = findViewById(R.id.btnCopy);

        tvFree = findViewById(R.id.tvFree);
        storageBar = findViewById(R.id.storageBar);
        tvSessions = findViewById(R.id.tvSessions);

        liveStopSection = findViewById(R.id.liveStopSection);
        btnStop = findViewById(R.id.btnStop);
        btnOwner = findViewById(R.id.btnOwner);

        applyInsets();
        loadTokens();
        ensureExternalDir();

        // Orb tap dispatcher: starting when stopped
        orbView.setOnClickListener(v -> {
            if (state == AppState.STOPPED) {
                startServer();
            }
        });

        // Stage Handoff card tap: safe for pocket taps, copies link
        handoffCard.setOnClickListener(v -> copyLink());

        btnCopy.setOnClickListener(v -> copyLink());

        btnFlipHost.setOnClickListener(v -> {
            preferTunnel = !preferTunnel;
            render(lastHealth);
            toast(preferTunnel ? "Using Cloudflare tunnel link" : "Using local Wi-Fi link");
        });

        btnStop.setOnClickListener(v -> {
            btnStop.setEnabled(false);
            exec.execute(() -> {
                String raw = httpGet("http://127.0.0.1:" + PORT + "/healthz", dropToken);
                Health liveHealth = (raw != null) ? Health.parse(raw) : lastHealth;
                handler.post(() -> {
                    btnStop.setEnabled(true);
                    if (liveHealth.isUploading || liveHealth.isActive) {
                        showActiveUploadWarning(liveHealth);
                    } else {
                        stopServer();
                    }
                });
            });
        });

        btnOwner.setOnClickListener(v -> {
            String target = (preferTunnel && !publicUrl.isEmpty())
                    ? publicUrl
                    : (!lanIp.isEmpty() ? "http://" + lanIp + ":" + PORT : "http://127.0.0.1:" + PORT);
            String url = target + "/owner?k=" + ownerToken;
            try {
                startActivity(new Intent(Intent.ACTION_VIEW, Uri.parse(url)));
            } catch (Exception e) {
                toast("Could not open browser");
            }
        });

        btnFixPerm.setOnClickListener(v -> {
            try {
                Intent intent = new Intent(Settings.ACTION_APPLICATION_DETAILS_SETTINGS);
                intent.setData(Uri.parse("package:" + getPackageName()));
                startActivity(intent);
            } catch (Exception e) {
                toast("Open Settings to grant Termux permission");
            }
        });

        pressFeedback(btnCopy);
        pressFeedback(btnStop);
        pressFeedback(btnFlipHost);

        applyState(AppState.STOPPED, Health.down());
    }

    @Override
    protected void onResume() {
        super.onResume();
        if (Termux.permitted(this)) {
            bootstrap();
        }
        refresh();
        poller = new Runnable() {
            @Override
            public void run() {
                refresh();
                handler.postDelayed(this, 7000);
            }
        };
        handler.postDelayed(poller, 7000);
    }

    @Override
    protected void onPause() {
        super.onPause();
        if (poller != null) {
            handler.removeCallbacks(poller);
            poller = null;
        }
    }

    private void applyInsets() {
        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.R) {
            findViewById(R.id.rootLayout).setOnApplyWindowInsetsListener((v, insets) -> {
                Insets sys = insets.getInsets(WindowInsets.Type.systemBars());
                statusStrip.setPadding(dp(20), sys.top + dp(10), dp(20), dp(12));
                sheet.setPadding(dp(20), dp(10), dp(20), sys.bottom + dp(14));
                return WindowInsets.CONSUMED;
            });
        }
    }

    private void pressFeedback(View v) {
        v.setOnTouchListener((view, event) -> {
            switch (event.getAction()) {
                case MotionEvent.ACTION_DOWN:
                    view.animate().scaleX(0.97f).scaleY(0.97f).setDuration(120).setInterpolator(EASE).start();
                    break;
                case MotionEvent.ACTION_UP:
                case MotionEvent.ACTION_CANCEL:
                    view.animate().scaleX(1.0f).scaleY(1.0f).setDuration(120).setInterpolator(EASE).start();
                    break;
            }
            return false;
        });
    }

    // ---- Server Commands ---------------------------------------------------

    void startServer() {
        if (!Termux.permitted(this)) {
            render(lastHealth);
            return;
        }
        starting = true;
        render(lastHealth);
        sendCmd(new String[]{"start"}, "Starting Photo Drop");
        handler.postDelayed(this::refresh, 4000);
        handler.postDelayed(this::refresh, 8000);
    }

    void showActiveUploadWarning(Health h) {
        int uploaders = Math.max(h.uploadersCount, 1);
        String personWord = (uploaders == 1) ? "1 person is" : (uploaders + " people are");
        List<String> allFiles = h.allTransferFiles();
        int count = Math.max(allFiles.size(), h.inFlightCount);

        StringBuilder sb = new StringBuilder();
        sb.append(personWord).append(" currently uploading ")
                .append(count).append(count == 1 ? " file" : " files")
                .append(" to this device:\n\n");

        int shown = 0;
        for (String f : h.inFlightFiles) {
            sb.append("• ").append(f).append(" (uploading now)\n");
            shown++;
            if (shown >= 6) break;
        }
        if (shown < 6) {
            for (String f : h.recentFiles) {
                if (!h.inFlightFiles.contains(f)) {
                    sb.append("• ").append(f).append(" (recently uploaded)\n");
                    shown++;
                    if (shown >= 6) break;
                }
            }
        }
        int remaining = count - shown;
        if (remaining > 0) {
            sb.append("• ... and ").append(remaining).append(" more ").append(remaining == 1 ? "file" : "files").append("\n");
        }

        sb.append("\nStopping now will cancel their in-flight upload and disconnect them.");

        new AlertDialog.Builder(this)
                .setTitle("⚠️ Active Upload in Progress")
                .setMessage(sb.toString())
                .setPositiveButton("Stop anyway", (d, which) -> stopServer())
                .setNegativeButton("Keep running", null)
                .show();
    }

    void stopServer() {
        starting = false;
        toast("Stopping Photo Drop...");
        applyState(AppState.STOPPED, Health.down());

        PhotoDropService.stop(this);

        exec.execute(() -> {
            // 1. Direct HTTP shutdown request to running server on loopback
            try {
                URL u = new URL("http://127.0.0.1:" + PORT + "/api/stop?k=" + ownerToken);
                HttpURLConnection conn = (HttpURLConnection) u.openConnection();
                conn.setRequestMethod("POST");
                conn.setConnectTimeout(1500);
                conn.setReadTimeout(1500);
                conn.getResponseCode();
                conn.disconnect();
            } catch (Exception ignored) {
            }

            // 2. Termux run command fallback
            Termux.stop(MainActivity.this);
        });

        handler.postDelayed(this::refresh, 1200);
        handler.postDelayed(this::refresh, 3000);
    }

    void sendCmd(String[] args, String label) {
        if (!Termux.permitted(this)) {
            toast("Termux permission missing");
            return;
        }
        exec.execute(() -> {
            boolean ok = Termux.run(this, args);
            if (!ok) {
                handler.post(() -> toast("Failed to send command to Termux"));
            }
        });
    }

    void bootstrap() {
        exec.execute(() -> Termux.bootstrap(this, dropToken, ownerToken));
    }

    // ---- Tokens & Storage --------------------------------------------------

    void loadTokens() {
        SharedPreferences p = getSharedPreferences(PREFS, MODE_PRIVATE);
        dropToken = p.getString(K_DROP, "");
        ownerToken = p.getString(K_OWNER, "");
        if (dropToken.isEmpty() || ownerToken.isEmpty()) {
            dropToken = mintToken();
            ownerToken = mintToken();
            p.edit().putString(K_DROP, dropToken).putString(K_OWNER, ownerToken).apply();
        }
    }

    static String mintToken() {
        byte[] b = new byte[18];
        new SecureRandom().nextBytes(b);
        return java.util.Base64.getUrlEncoder().withoutPadding().encodeToString(b);
    }

    void ensureExternalDir() {
        try {
            File d = getExternalFilesDir(null);
            if (d != null && !d.exists()) d.mkdirs();
        } catch (Exception ignored) {}
    }

    // ---- Polling & Status --------------------------------------------------

    void refresh() {
        exec.execute(() -> {
            String rawHealth = httpGet("http://127.0.0.1:" + PORT + "/healthz", dropToken);
            Health h = Health.parse(rawHealth);
            String url = readPublicUrl();
            if (url.isEmpty() && !h.publicUrl.isEmpty()) {
                url = h.publicUrl;
            }
            String lan = h.lanIp;
            if (lan.isEmpty()) {
                lan = detectDeviceIp();
            }

            final String finalUrl = url;
            final String finalLan = lan;
            handler.post(() -> {
                publicUrl = finalUrl;
                lanIp = finalLan;
                render(h);
            });
        });
    }

    AppState classify(Health h, boolean permitted) {
        if (!permitted) return AppState.TERMUX_ERROR;
        if (!h.up) return starting ? AppState.STARTING : AppState.STOPPED;
        starting = false;
        if (h.isLow()) return AppState.STORAGE_LOW;
        if (preferTunnel && !publicUrl.isEmpty()) return AppState.ONLINE_TUNNEL;
        return AppState.ONLINE_LOCAL;
    }

    void render(Health h) {
        boolean permitted = Termux.permitted(this);
        AppState next = classify(h, permitted);
        this.lastHealth = h;
        this.state = next;
        applyState(next, h);

        // Keep foreground service notification in step
        if (h.up) {
            String share = currentShareUrl();
            PhotoDropService.start(this, share, domainOf(share),
                    h.known() ? human(h.free) : "");
        } else {
            PhotoDropService.stop(this);
        }
    }

    void applyState(AppState s, Health h) {
        // Storage readout (common to all states)
        if (h.known()) {
            boolean low = h.isLow();
            tvFree.setText(human(h.free) + " free");
            tvFree.setTextColor(low ? 0xFF8C1D18 : getColor(R.color.text_main));
            storageBar.setState(h.freeRatio(), h.reserveRatio());
        } else {
            tvFree.setText("-- free");
            tvFree.setTextColor(getColor(R.color.text_muted));
            storageBar.setState(0f, 0f);
        }
        if (h.isUploading) {
            tvSessions.setText(h.inFlightCount + (h.inFlightCount == 1 ? " UPLOADING" : " UPLOADING"));
            tvSessions.setBackgroundResource(R.drawable.pill_warning);
            tvSessions.setTextColor(0xFF8C1D18);
        } else if (h.isActive) {
            tvSessions.setText("ACTIVE");
            tvSessions.setBackgroundResource(R.drawable.pill_success);
            tvSessions.setTextColor(getColor(R.color.success));
        } else {
            tvSessions.setText(h.sessions + (h.sessions == 1 ? " SESSION" : " SESSIONS"));
            tvSessions.setBackgroundResource(h.sessions > 0 ? R.drawable.pill_success : R.drawable.pill_neutral);
            tvSessions.setTextColor(h.sessions > 0 ? getColor(R.color.success) : getColor(R.color.text_muted));
        }

        // State layout switching
        switch (s) {
            case STOPPED:
                statusStrip.setState(StatusStripView.State.STOPPED, "Server is offline", "Nothing can upload right now");
                orbStage.setVisibility(View.VISIBLE);
                orbView.setMode(OrbView.Mode.STOPPED);
                tvOrbCaption.setText("One tap and this becomes a link you can hand to a friend.");
                handoffCard.setVisibility(View.GONE);
                alertCard.setVisibility(View.GONE);
                permCard.setVisibility(View.GONE);
                liveControls.setVisibility(View.GONE);
                liveStopSection.setVisibility(View.GONE);
                break;

            case STARTING:
                statusStrip.setState(StatusStripView.State.STARTING, "Starting", "Bringing up Termux and tunnel...");
                orbStage.setVisibility(View.VISIBLE);
                orbView.setMode(OrbView.Mode.STARTING);
                tvOrbCaption.setText("Bringing up the server and negotiating the upload link.");
                handoffCard.setVisibility(View.GONE);
                alertCard.setVisibility(View.GONE);
                permCard.setVisibility(View.GONE);
                liveControls.setVisibility(View.GONE);
                liveStopSection.setVisibility(View.GONE);
                break;

            case ONLINE_LOCAL:
            case ONLINE_TUNNEL:
                orbStage.setVisibility(View.GONE);
                alertCard.setVisibility(View.GONE);
                permCard.setVisibility(View.GONE);
                handoffCard.setVisibility(View.VISIBLE);
                liveControls.setVisibility(View.VISIBLE);
                liveStopSection.setVisibility(View.VISIBLE);

                String shareUrl = currentShareUrl();
                String domain = domainOf(shareUrl);
                tvDropDomain.setText(domain);
                tvDropUrl.setText(shareUrl);
                tvSheetUrl.setText(shareUrl);

                if (s == AppState.ONLINE_TUNNEL) {
                    statusStrip.setState(StatusStripView.State.ONLINE_TUNNEL,
                            "Online anywhere",
                            (h.sessions > 0 ? h.sessions + (h.sessions == 1 ? " session · " : " sessions · ") : "") + "Works for anyone with the link");
                    tvDockedBadge.setText("● LIVE");
                    tvDockedBadge.setBackgroundResource(R.drawable.badge_live);
                    tvDropHint.setText("They scan, pick photos, watch them upload. Nothing is installed on their phone.");
                } else {
                    statusStrip.setState(StatusStripView.State.ONLINE_LOCAL,
                            "On this Wi-Fi",
                            (h.sessions > 0 ? h.sessions + (h.sessions == 1 ? " session · " : " sessions · ") : "") + "Works for devices on this network");
                    tvDockedBadge.setText("● ON WI-FI");
                    tvDockedBadge.setBackgroundResource(R.drawable.badge_live);
                    tvDropHint.setText("Reachable on this Wi-Fi network. Scan to open the upload page.");
                }

                // Render or update QR Code if URL changed
                if (!shareUrl.equals(qrForUrl) && !shareUrl.isEmpty()) {
                    Bitmap bmp = qrBitmap(shareUrl, dp(184));
                    if (bmp != null) {
                        imgQr.setImageBitmap(bmp);
                        qrForUrl = shareUrl;
                    }
                }
                break;

            case STORAGE_LOW:
                statusStrip.setState(StatusStripView.State.STORAGE_LOW, "Storage low", "Uploads are paused to protect device");
                orbStage.setVisibility(View.GONE);
                handoffCard.setVisibility(View.GONE);
                alertCard.setVisibility(View.VISIBLE);
                permCard.setVisibility(View.GONE);
                liveControls.setVisibility(View.VISIBLE);
                liveStopSection.setVisibility(View.VISIBLE);
                tvAlertDesc.setText("Uploads are paused at " + human(h.reserve) + " free to keep your phone healthy. Free up space to resume.");
                break;

            case TERMUX_ERROR:
                statusStrip.setState(StatusStripView.State.TERMUX_ERROR, "Can't reach Termux", "Grant permission to run commands");
                orbStage.setVisibility(View.GONE);
                handoffCard.setVisibility(View.GONE);
                alertCard.setVisibility(View.GONE);
                permCard.setVisibility(View.VISIBLE);
                liveControls.setVisibility(View.GONE);
                liveStopSection.setVisibility(View.GONE);
                break;
        }
    }

    void copyLink() {
        if (!lastHealth.up) {
            toast("Start the server first");
            return;
        }
        String url = currentShareUrl();
        copy(url);
        btnCopy.setText("Copied to clipboard!");
        if (copyReset != null) handler.removeCallbacks(copyReset);
        copyReset = () -> btnCopy.setText("Copy link to send");
        handler.postDelayed(copyReset, 2200);
    }

    String currentShareUrl() {
        String base;
        if (preferTunnel && !publicUrl.isEmpty()) {
            base = publicUrl;
        } else if (!lanIp.isEmpty()) {
            base = "http://" + lanIp + ":" + PORT;
        } else if (!publicUrl.isEmpty()) {
            base = publicUrl;
        } else {
            base = "http://" + detectDeviceIp() + ":" + PORT;
        }
        return base + "/d/" + dropToken + "/";
    }

    String readPublicUrl() {
        File[] cands = new File[]{
            new File(getExternalFilesDir(null), "public-url.txt"),
            new File("/sdcard/Android/data/dev.photodrop.app/files/public-url.txt")
        };
        for (File f : cands) {
            try {
                if (f == null || !f.exists() || !f.canRead()) continue;
                BufferedReader br = new BufferedReader(new FileReader(f));
                String line = br.readLine();
                br.close();
                if (line != null && !line.trim().isEmpty()) return line.trim();
            } catch (Exception ignored) {}
        }
        return "";
    }

    String detectDeviceIp() {
        try {
            List<NetworkInterface> interfaces = Collections.list(NetworkInterface.getNetworkInterfaces());
            for (NetworkInterface intf : interfaces) {
                if (intf.isLoopback() || !intf.isUp()) continue;
                List<InetAddress> addrs = Collections.list(intf.getInetAddresses());
                for (InetAddress addr : addrs) {
                    if (!addr.isLoopbackAddress() && addr instanceof Inet4Address) {
                        return addr.getHostAddress();
                    }
                }
            }
        } catch (Exception ignored) {}
        return "127.0.0.1";
    }

    Bitmap qrBitmap(String content, int size) {
        try {
            BitMatrix m = new QRCodeWriter().encode(
                    content, BarcodeFormat.QR_CODE, size, size);
            int w = m.getWidth(), h = m.getHeight();
            int[] px = new int[w * h];
            for (int y = 0; y < h; y++) {
                int row = y * w;
                for (int x = 0; x < w; x++) {
                    px[row + x] = m.get(x, y) ? 0xFF111315 : 0xFFFFFFFF;
                }
            }
            return Bitmap.createBitmap(px, w, h, Bitmap.Config.ARGB_8888);
        } catch (WriterException e) {
            Log.w("PhotoDrop", "qr encode failed", e);
            return null;
        }
    }

    static String domainOf(String url) {
        if (url == null || url.isEmpty()) return "this phone";
        String rest = url;
        int i = rest.indexOf("://");
        if (i >= 0) rest = rest.substring(i + 3);
        int slash = rest.indexOf('/');
        String host = slash >= 0 ? rest.substring(0, slash) : rest;
        int colon = host.lastIndexOf(':');
        if (colon > 0 && host.indexOf(':') == colon) host = host.substring(0, colon);
        if (host.isEmpty() || host.equals("127.0.0.1") || host.equals("localhost") || host.equals("0.0.0.0")) {
            return "this phone";
        }
        if (host.matches("\\d{1,3}(\\.\\d{1,3}){3}")) return host;
        String[] parts = host.split("\\.");
        if (parts.length >= 2) return parts[parts.length - 2] + "." + parts[parts.length - 1];
        return host;
    }

    String httpGet(String url, String token) {
        HttpURLConnection c = null;
        try {
            c = (HttpURLConnection) new URL(url).openConnection();
            c.setConnectTimeout(2500);
            c.setReadTimeout(3500);
            if (token != null) c.setRequestProperty("X-PD-Token", token);
            c.setInstanceFollowRedirects(false);
            if (c.getResponseCode() != 200) return null;
            BufferedReader br = new BufferedReader(
                    new java.io.InputStreamReader(c.getInputStream()));
            StringBuilder sb = new StringBuilder();
            String line;
            while ((line = br.readLine()) != null) sb.append(line);
            br.close();
            return sb.toString();
        } catch (Exception e) {
            return null;
        } finally {
            if (c != null) c.disconnect();
        }
    }

    static String human(long bytes) {
        if (bytes < 0) return "--";
        double b = bytes;
        String[] u = {"B", "KB", "MB", "GB", "TB"};
        int i = 0;
        while (b >= 1024 && i < u.length - 1) { b /= 1024; i++; }
        return String.format(java.util.Locale.US, "%.1f %s", b, u[i]);
    }

    void copy(String text) {
        ClipboardManager cm = (ClipboardManager) getSystemService(Context.CLIPBOARD_SERVICE);
        if (cm != null) {
            cm.setPrimaryClip(ClipData.newPlainText("Photo Drop", text));
        }
    }

    void toast(String msg) {
        Toast.makeText(this, msg, Toast.LENGTH_SHORT).show();
    }

    int dp(float v) {
        return Math.round(v * getResources().getDisplayMetrics().density);
    }
}
