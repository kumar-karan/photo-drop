package dev.photodrop.app;

import android.app.Notification;
import android.app.NotificationChannel;
import android.app.NotificationManager;
import android.app.PendingIntent;
import android.app.Service;
import android.content.Context;
import android.content.Intent;
import android.content.SharedPreferences;
import android.os.Build;
import android.os.Handler;
import android.os.IBinder;
import android.os.Looper;

import java.io.BufferedReader;
import java.io.File;
import java.io.FileOutputStream;
import java.io.InputStreamReader;
import java.net.HttpURLConnection;
import java.net.URL;
import java.util.ArrayList;
import java.util.List;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;

/**
 * Keeps a visible claim and live notification on the running server.
 *
 * Actively polls /healthz on loopback so the notification always reflects:
 *  - Current remaining storage ("115.3 GB free")
 *  - In-flight upload file names and progress count
 *  - Liveness heartbeat for the Termux watchdog
 */
public class PhotoDropService extends Service {

    static final String CHANNEL = "photodrop_status";
    static final int NOTIF_ID = 1;
    static final String ACTION_STOP = "dev.photodrop.app.action.STOP";
    static final String ACTION_UPDATE = "dev.photodrop.app.action.UPDATE";
    static final String E_URL = "url";
    static final String E_DOMAIN = "domain";
    static final String E_FREE = "free";

    private static volatile PhotoDropService instance = null;

    private String url = "";
    private String domain = "";
    private String free = "";
    private boolean isUploading = false;
    private int inFlightCount = 0;
    private List<String> inFlightFiles = new ArrayList<>();

    private static final File HEARTBEAT = new File(
            "/sdcard/Android/data/dev.photodrop.app/files/heartbeat");
    private static final long POLL_MS = 3000;

    private final Handler mainHandler = new Handler(Looper.getMainLooper());
    private ExecutorService bgExec;

    private final Runnable pollTicker = new Runnable() {
        @Override
        public void run() {
            beat();
            pollHealth();
            mainHandler.postDelayed(this, POLL_MS);
        }
    };

    private void beat() {
        try {
            File d = HEARTBEAT.getParentFile();
            if (d != null && !d.exists()) d.mkdirs();
            FileOutputStream out = new FileOutputStream(HEARTBEAT);
            try {
                out.write(Long.toString(System.currentTimeMillis()).getBytes("UTF-8"));
            } finally {
                out.close();
            }
        } catch (Exception ignored) {
        }
    }

    public static void start(Context c, String url, String domain, String free) {
        Intent i = new Intent(c, PhotoDropService.class);
        i.putExtra(E_URL, url);
        i.putExtra(E_DOMAIN, domain);
        i.putExtra(E_FREE, free);
        c.startForegroundService(i);
    }

    public static void stop(Context c) {
        c.stopService(new Intent(c, PhotoDropService.class));
    }

    public static void updateWithHealth(Context c, Health h, String currentUrl, String currentDomain) {
        if (instance != null) {
            instance.applyHealth(h, currentUrl, currentDomain);
        }
    }

    @Override
    public void onCreate() {
        super.onCreate();
        instance = this;
        bgExec = Executors.newSingleThreadExecutor();
        NotificationManager nm = (NotificationManager) getSystemService(NOTIFICATION_SERVICE);
        if (nm != null && Build.VERSION.SDK_INT >= Build.VERSION_CODES.O) {
            NotificationChannel ch = new NotificationChannel(
                    CHANNEL, "Photo Drop server", NotificationManager.IMPORTANCE_LOW);
            ch.setDescription("Shown while the upload server is running");
            ch.setShowBadge(false);
            ch.enableVibration(false);
            nm.createNotificationChannel(ch);
        }
    }

    @Override
    public int onStartCommand(Intent intent, int flags, int startId) {
        if (intent != null && ACTION_STOP.equals(intent.getAction())) {
            shutdown();
            return START_NOT_STICKY;
        }
        if (intent != null) {
            url = or(intent.getStringExtra(E_URL), url);
            domain = or(intent.getStringExtra(E_DOMAIN), domain);
            String f = intent.getStringExtra(E_FREE);
            if (f != null && !f.isEmpty()) free = f;
        }

        startForeground(NOTIF_ID, build());

        mainHandler.removeCallbacks(pollTicker);
        mainHandler.post(pollTicker);

        return START_NOT_STICKY;
    }

    private void pollHealth() {
        if (bgExec == null || bgExec.isShutdown()) return;
        bgExec.execute(() -> {
            try {
                SharedPreferences p = getSharedPreferences("photodrop", MODE_PRIVATE);
                String token = p.getString("drop_token", "");
                URL u = new URL("http://127.0.0.1:8080/healthz");
                HttpURLConnection conn = (HttpURLConnection) u.openConnection();
                conn.setRequestMethod("GET");
                conn.setConnectTimeout(1800);
                conn.setReadTimeout(1800);
                if (!token.isEmpty()) {
                    conn.setRequestProperty("X-PD-Token", token);
                }
                if (conn.getResponseCode() == 200) {
                    BufferedReader r = new BufferedReader(new InputStreamReader(conn.getInputStream()));
                    StringBuilder sb = new StringBuilder();
                    String line;
                    while ((line = r.readLine()) != null) sb.append(line);
                    r.close();
                    Health h = Health.parse(sb.toString());
                    if (h.up) {
                        mainHandler.post(() -> applyHealth(h, null, null));
                    }
                }
                conn.disconnect();
            } catch (Exception ignored) {
            }
        });
    }

    public void applyHealth(Health h, String overrideUrl, String overrideDomain) {
        if (overrideUrl != null && !overrideUrl.isEmpty()) url = overrideUrl;
        if (overrideDomain != null && !overrideDomain.isEmpty()) domain = overrideDomain;

        if (h != null && h.known()) {
            this.free = Health.human(h.free);
            this.isUploading = h.isUploading;
            this.inFlightCount = h.inFlightCount;
            this.inFlightFiles = new ArrayList<>(h.inFlightFiles);
            if (this.url.isEmpty() && !h.publicUrl.isEmpty()) {
                this.url = h.publicUrl;
                this.domain = extractDomain(h.publicUrl);
            }
            NotificationManager nm = (NotificationManager) getSystemService(NOTIFICATION_SERVICE);
            if (nm != null) {
                nm.notify(NOTIF_ID, build());
            }
        }
    }

    private static String extractDomain(String raw) {
        try {
            return new URL(raw).getHost();
        } catch (Exception e) {
            return raw;
        }
    }

    static String or(String s, String fallback) {
        return s == null || s.isEmpty() ? fallback : s;
    }

    Notification build() {
        Intent open = getPackageManager().getLaunchIntentForPackage(getPackageName());
        PendingIntent openPi = null;
        if (open != null) {
            open.addFlags(Intent.FLAG_ACTIVITY_NEW_TASK | Intent.FLAG_ACTIVITY_CLEAR_TOP);
            openPi = PendingIntent.getActivity(this, 0, open,
                    PendingIntent.FLAG_UPDATE_CURRENT | PendingIntent.FLAG_IMMUTABLE);
        }

        Intent stopIntent = new Intent(this, PhotoDropService.class).setAction(ACTION_STOP);
        PendingIntent stopPi = PendingIntent.getForegroundService(this, 1, stopIntent,
                PendingIntent.FLAG_UPDATE_CURRENT | PendingIntent.FLAG_IMMUTABLE);

        Notification.Builder b;
        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.O) {
            b = new Notification.Builder(this, CHANNEL);
        } else {
            b = new Notification.Builder(this);
            b.setPriority(Notification.PRIORITY_LOW);
        }

        b.setOngoing(true)
                .setOnlyAlertOnce(true)
                .setShowWhen(false)
                .setCategory(Notification.CATEGORY_SERVICE)
                .setVisibility(Notification.VISIBILITY_PUBLIC);

        if (openPi != null) b.setContentIntent(openPi);

        b.addAction(new Notification.Action.Builder(
                android.R.drawable.ic_menu_close_clear_cancel, "Stop", stopPi).build());

        if (isUploading) {
            b.setSmallIcon(android.R.drawable.stat_sys_upload);
            String title = "Uploading " + inFlightCount + (inFlightCount == 1 ? " file" : " files")
                    + (!free.isEmpty() ? "  ·  " + free + " free" : "");
            b.setContentTitle(title);

            String fileStr = (!inFlightFiles.isEmpty()) ? inFlightFiles.get(0) : "Receiving photos";
            if (inFlightCount > 1) {
                fileStr += " (+" + (inFlightCount - 1) + " more)";
            }
            b.setContentText(fileStr);

            StringBuilder big = new StringBuilder();
            big.append("Upload in progress:\n");
            for (String f : inFlightFiles) {
                big.append("• ").append(f).append("\n");
            }
            if (!free.isEmpty()) {
                big.append("\nStorage remaining: ").append(free).append(" free");
            }
            if (!url.isEmpty()) {
                big.append("\nDrop link:\n").append(url);
            }
            b.setStyle(new Notification.BigTextStyle().bigText(big.toString()));
        } else {
            b.setSmallIcon(android.R.drawable.stat_sys_upload_done);
            String title = free.isEmpty() ? "Photo Drop server is running" : "Photo Drop  ·  " + free + " free";
            b.setContentTitle(title);

            String body = domain.isEmpty() ? "Server is ready for uploads" : domain;
            if (!free.isEmpty()) body = body + "  ·  " + free + " free";
            b.setContentText(body);

            if (!url.isEmpty()) {
                b.setStyle(new Notification.BigTextStyle().bigText(
                        "Ready for uploads" + (!free.isEmpty() ? "  ·  " + free + " free\n\n" : "\n\n")
                                + "Your friend uploads here:\n" + url
                                + "\n\nSwipe the app out of recents to stop the server."));
            }
        }

        return b.build();
    }

    void shutdown() {
        mainHandler.removeCallbacks(pollTicker);
        if (bgExec != null) {
            bgExec.shutdownNow();
            bgExec = null;
        }
        instance = null;
        File hb = new File(getExternalFilesDir(null), "heartbeat");
        if (hb.exists()) hb.delete();

        new Thread(() -> {
            try {
                URL u = new URL("http://127.0.0.1:8080/api/stop");
                HttpURLConnection conn = (HttpURLConnection) u.openConnection();
                conn.setRequestMethod("POST");
                conn.setConnectTimeout(1500);
                conn.setReadTimeout(1500);
                conn.getResponseCode();
                conn.disconnect();
            } catch (Exception ignored) {
            }
            Termux.stop(PhotoDropService.this);
        }).start();

        stopForeground(true);
        stopSelf();
    }

    @Override
    public void onTaskRemoved(Intent rootIntent) {
        mainHandler.removeCallbacks(pollTicker);
        shutdown();
        super.onTaskRemoved(rootIntent);
    }

    @Override
    public void onDestroy() {
        mainHandler.removeCallbacks(pollTicker);
        if (bgExec != null) {
            bgExec.shutdownNow();
            bgExec = null;
        }
        instance = null;
        File hb = new File(getExternalFilesDir(null), "heartbeat");
        if (hb.exists()) hb.delete();
        stopForeground(true);
        super.onDestroy();
    }

    @Override
    public IBinder onBind(Intent intent) { return null; }
}
