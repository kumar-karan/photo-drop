package dev.photodrop.app;

import org.json.JSONArray;
import org.json.JSONObject;

import java.util.ArrayList;
import java.util.Collections;
import java.util.List;

/**
 * Value object representing /healthz diagnostics.
 */
public final class Health {
    public final boolean up;
    public final long free;
    public final long total;
    public final long reserve;
    public final int sessions;
    public final String publicUrl;
    public final String lanIp;

    // Active upload stats
    public final boolean isUploading;
    public final boolean isActive;
    public final int uploadersCount;
    public final int inFlightCount;
    public final List<String> inFlightFiles;
    public final int recentCount;
    public final List<String> recentFiles;

    public Health(boolean up, long free, long total, long reserve, int sessions,
                  String publicUrl, String lanIp,
                  boolean isUploading, boolean isActive, int uploadersCount,
                  int inFlightCount, List<String> inFlightFiles,
                  int recentCount, List<String> recentFiles) {
        this.up = up;
        this.free = free;
        this.total = total;
        this.reserve = reserve;
        this.sessions = sessions;
        this.publicUrl = publicUrl != null ? publicUrl.trim() : "";
        this.lanIp = lanIp != null ? lanIp.trim() : "";
        this.isUploading = isUploading;
        this.isActive = isActive;
        this.uploadersCount = uploadersCount;
        this.inFlightCount = inFlightCount;
        this.inFlightFiles = inFlightFiles != null ? Collections.unmodifiableList(inFlightFiles) : Collections.emptyList();
        this.recentCount = recentCount;
        this.recentFiles = recentFiles != null ? Collections.unmodifiableList(recentFiles) : Collections.emptyList();
    }

    public static Health down() {
        return new Health(false, -1, -1, -1, 0, "", "", false, false, 0, 0, Collections.emptyList(), 0, Collections.emptyList());
    }

    public static Health parse(String body) {
        if (body == null || body.trim().isEmpty()) {
            return down();
        }
        try {
            JSONObject j = new JSONObject(body);
            boolean ok = j.optBoolean("ok", false);
            long free = j.optLong("free", -1);
            long total = j.optLong("dest_size", -1);
            long reserve = j.optLong("reserve", -1);
            int sessions = j.optInt("sessions", 0);
            String pubUrl = j.optString("public_url", "");
            String lan = j.optString("lan_ip", "");

            boolean isUploading = false;
            boolean isActive = false;
            int uploaders = 0;
            int inFlightCount = 0;
            List<String> inFlightFiles = new ArrayList<>();
            int recentCount = 0;
            List<String> recentFiles = new ArrayList<>();

            JSONObject uStats = j.optJSONObject("upload_stats");
            if (uStats != null) {
                isUploading = uStats.optBoolean("uploading", false);
                isActive = uStats.optBoolean("active", false);
                uploaders = uStats.optInt("uploaders", 0);
                inFlightCount = uStats.optInt("in_flight_count", 0);
                JSONArray infArr = uStats.optJSONArray("in_flight_files");
                if (infArr != null) {
                    for (int i = 0; i < infArr.length(); i++) {
                        String s = infArr.optString(i, "");
                        if (!s.isEmpty()) inFlightFiles.add(s);
                    }
                }
                recentCount = uStats.optInt("recent_count", 0);
                JSONArray recArr = uStats.optJSONArray("recent_files");
                if (recArr != null) {
                    for (int i = 0; i < recArr.length(); i++) {
                        String s = recArr.optString(i, "");
                        if (!s.isEmpty()) recentFiles.add(s);
                    }
                }
            }

            return new Health(ok, free, total, reserve, sessions, pubUrl, lan,
                    isUploading, isActive, uploaders, inFlightCount, inFlightFiles, recentCount, recentFiles);
        } catch (Exception e) {
            return down();
        }
    }

    public List<String> allTransferFiles() {
        List<String> all = new ArrayList<>(inFlightFiles);
        for (String f : recentFiles) {
            if (!all.contains(f)) {
                all.add(f);
            }
        }
        return all;
    }

    public boolean known() {
        return free >= 0;
    }

    public boolean isLow() {
        return known() && reserve > 0 && free <= reserve;
    }

    public float freeRatio() {
        if (total <= 0 || free < 0) return 0f;
        return (float) free / (float) total;
    }

    public float reserveRatio() {
        if (total <= 0 || reserve < 0) return 0f;
        return (float) reserve / (float) total;
    }
}
