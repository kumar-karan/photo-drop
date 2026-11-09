package dev.photodrop.app;

import android.app.Notification;
import android.app.NotificationChannel;
import android.app.NotificationManager;
import android.app.PendingIntent;
import android.app.Service;
import android.content.Context;
import android.content.Intent;
import android.os.Build;
import android.os.IBinder;

import java.io.File;
import java.io.FileOutputStream;

/**
 * Keeps a visible claim on the running server.
 *
 * Two jobs, and they pull in opposite directions on purpose:
 *
 *  1. While the server runs there is a permanent notification. The server is a
 *     public upload endpoint reachable from anywhere, so it must never be
 *     something you have to guess about. If you can see it, it is on.
 *
 *  2. If the task is swiped out of recents, the server stops. A service
 *     outlives its task by default, which means a tunnel would keep serving
 *     after the app looked closed. That is the failure mode worth avoiding:
 *     you would believe you had shut it down while your link stayed live.
 *
 * Backgrounding the app does NOT stop it. That is the case the notification is
 * for: you have closed the screen deliberately and can see it is still up.
 */
public class PhotoDropService extends Service {

    static final String CHANNEL = "photodrop_status";
    static final int NOTIF_ID = 1;
    static final String ACTION_STOP = "dev.photodrop.app.action.STOP";
    static final String E_URL = "url";
    static final String E_DOMAIN = "domain";
    static final String E_FREE = "free";

    private String url = "";
    private String domain = "";
    private String free = "";

    /**
     * Liveness beacon for the watchdog in pd-control.sh.
     *
     * The obvious implementation, stopping Termux from onTaskRemoved, does not
     * reliably work: Android blocks startService for another app once we are
     * being torn down, so the teardown command silently never lands and the
     * tunnel keeps serving. Writing a heartbeat sidesteps that entirely. The
     * service ticks it while alive; when the task is swiped away the service
     * dies, the file goes stale, and the watchdog shuts everything down.
     */
    private static final File HEARTBEAT = new File(
            "/sdcard/Android/data/dev.photodrop.app/files/heartbeat");
    private static final long BEAT_MS = 5000;
    private final android.os.Handler beat =
            new android.os.Handler(android.os.Looper.getMainLooper());
    private final Runnable ticker = new Runnable() {
        @Override public void run() {
            beat();
            beat.postDelayed(this, BEAT_MS);
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
            // Losing one beat is fine. Losing all of them stops the server,
            // which is the fail-safe direction.
        }
    }

    /**
     * Deliberately does NOT delete the heartbeat.
     *
     * The watchdog treats an absent file as "not started yet" and keeps
     * waiting, so deleting it on teardown would silence the watchdog exactly
     * when it is needed. Staleness alone is the signal: the file stays, stops
     * being touched, and ages out.
     */

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

    @Override
    public void onCreate() {
        super.onCreate();
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
            url = or(intent.getStringExtra(E_URL), "");
            domain = or(intent.getStringExtra(E_DOMAIN), "");
            free = or(intent.getStringExtra(E_FREE), "");
        }
        startForeground(NOTIF_ID, build());
        // One immediate beat so a freshly started server is not mistaken for a
        // stale one while the first interval elapses.
        beat.removeCallbacks(ticker);
        beat.post(ticker);
        // Not sticky on purpose. If Android kills the service, the server should
        // not silently keep serving with nobody watching the notification.
        return START_NOT_STICKY;
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

        String body = domain.isEmpty() ? "Server is running" : domain;
        if (!free.isEmpty()) body = body + "  ·  " + free + " free";

        Notification.Builder b;
        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.O) {
            b = new Notification.Builder(this, CHANNEL);
        } else {
            b = new Notification.Builder(this);
            b.setPriority(Notification.PRIORITY_LOW);
        }

        b.setSmallIcon(android.R.drawable.stat_sys_upload_done)
                .setContentTitle("Photo Drop server is running")
                .setContentText(body)
                .setOngoing(true)
                .setOnlyAlertOnce(true)
                .setShowWhen(false)
                .setCategory(Notification.CATEGORY_SERVICE)
                .setVisibility(Notification.VISIBILITY_PUBLIC);

        if (openPi != null) b.setContentIntent(openPi);

        b.addAction(new Notification.Action.Builder(
                android.R.drawable.ic_menu_close_clear_cancel, "Stop", stopPi).build());

        // The collapsed view carries the domain; expanded it carries the link
        // itself, which is the one thing worth having in the shade.
        if (!url.isEmpty()) {
            b.setStyle(new Notification.BigTextStyle().bigText(
                    "Your friend uploads here.\n\n" + url
                            + "\n\nSwipe the app out of recents to stop the server."));
        }

        return b.build();
    }

    /** Stop the Termux server and drop the notification. */
    void shutdown() {
        beat.removeCallbacks(ticker);
        File hb = new File(getExternalFilesDir(null), "heartbeat");
        if (hb.exists()) hb.delete();

        new Thread(() -> {
            try {
                java.net.URL u = new java.net.URL("http://127.0.0.1:8080/api/stop");
                java.net.HttpURLConnection conn = (java.net.HttpURLConnection) u.openConnection();
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
        // Fast path: stop the ticking and trigger immediate shutdown via HTTP/Termux,
        // while the watchdog serves as an automated fallback if Android kills us.
        beat.removeCallbacks(ticker);
        shutdown();
        super.onTaskRemoved(rootIntent);
    }

    @Override
    public void onDestroy() {
        beat.removeCallbacks(ticker);
        File hb = new File(getExternalFilesDir(null), "heartbeat");
        if (hb.exists()) hb.delete();
        stopForeground(true);
        super.onDestroy();
    }

    @Override
    public IBinder onBind(Intent intent) { return null; }
}