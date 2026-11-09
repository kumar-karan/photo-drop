package dev.photodrop.app;

import android.content.Context;
import android.content.Intent;
import android.content.pm.PackageManager;

/**
 * The bridge to Termux.
 *
 * Both the Activity and the foreground Service need to drive the server, and
 * the Activity version also wants to tell the user when it fails, so the intent
 * plumbing lives here instead of being written twice.
 */
public final class Termux {
    private Termux() {}

    static final String PKG = "com.termux";
    static final String ACTION = "com.termux.RUN_COMMAND";
    static final String PERM = "com.termux.permission.RUN_COMMAND";
    static final String E_PATH = "com.termux.RUN_COMMAND_PATH";
    static final String E_ARGS = "com.termux.RUN_COMMAND_ARGUMENTS";
    static final String E_WORKDIR = "com.termux.RUN_COMMAND_WORKDIR";
    static final String E_BACKGROUND = "com.termux.RUN_COMMAND_BACKGROUND";
    static final String HOME = "/data/data/com.termux/files/home";
    static final String CONTROL = HOME + "/pd-control.sh";

    static boolean permitted(Context c) {
        return c.checkSelfPermission(PERM) == PackageManager.PERMISSION_GRANTED;
    }

    /** Fire and forget. Returns false only if Termux is not reachable at all. */
    static boolean run(Context c, String[] args) {
        if (!permitted(c)) return false;
        try {
            Intent i = new Intent(ACTION);
            i.setClassName(PKG, PKG + ".app.RunCommandService");
            i.putExtra(E_PATH, CONTROL);
            i.putExtra(E_ARGS, args);
            i.putExtra(E_WORKDIR, HOME);
            i.putExtra(E_BACKGROUND, true);
            c.startService(i);
            return true;
        } catch (Exception e) {
            return false;
        }
    }

    static boolean bootstrap(Context c, String drop, String owner) {
        return run(c, new String[]{"bootstrap", drop, owner});
    }

    static boolean start(Context c) { return run(c, new String[]{"start"}); }
    static boolean stop(Context c)  { return run(c, new String[]{"stop"}); }
}