package dev.photodrop.app;

import android.content.Context;
import android.graphics.Canvas;
import android.graphics.Paint;
import android.graphics.RectF;
import android.util.AttributeSet;
import android.view.View;

/**
 * Free-space gauge for the phone.
 *
 * The question this answers is "do I have room for my friend's photos", which is
 * a yes/no about how full the phone is rather than a precise figure. A bar reads
 * that faster than numerals, so the bar carries the shape of the answer and the
 * numerals beside it carry the precision.
 *
 * A tick marks the reserve, so the line that will stop uploads is visible
 * before it is hit rather than discovered as a failure.
 */
public class StorageBarView extends View {

    private final Paint track = new Paint(Paint.ANTI_ALIAS_FLAG);
    private final Paint fill = new Paint(Paint.ANTI_ALIAS_FLAG);
    private final Paint tick = new Paint(Paint.ANTI_ALIAS_FLAG);
    private final RectF r = new RectF();

    private static final int TRACK = 0xFFE6E9EC;
    private static final int OK = 0xFF167A38;
    private static final int LOW = 0xFFB3261E;
    private static final int TICK = 0xFF9AA1A8;

    private float ratio = 0f;
    private float reserve = 0f;

    public StorageBarView(Context c) { super(c); }
    public StorageBarView(Context c, AttributeSet a) { super(c, a); }
    public StorageBarView(Context c, AttributeSet a, int d) { super(c, a, d); }

    /** @param ratio fraction of the volume that is free, 0..1
     *  @param reserve fraction held back below which uploads pause, 0..1 */
    public void setState(float ratio, float reserve) {
        this.ratio = clamp01(ratio);
        this.reserve = clamp01(reserve);
        fill.setColor(this.ratio <= this.reserve ? LOW : OK);
        invalidate();
    }

    static float clamp01(float v) { return v < 0f ? 0f : (v > 1f ? 1f : v); }

    @Override
    protected void onDraw(Canvas canvas) {
        int w = getWidth();
        int h = getHeight();
        if (w <= 0 || h <= 0) return;

        float rad = Math.min(h / 2f, w / 2f);

        track.setColor(TRACK);
        r.left = 0; r.top = 0; r.right = w; r.bottom = h;
        canvas.drawRoundRect(r, rad, rad, track);

        // Never draw a fill so short it collapses into a blob.
        float fillW = w * ratio;
        if (fillW > 0) {
            r.right = Math.max(fillW, h);
            canvas.drawRoundRect(r, rad, rad, fill);
        }

        if (reserve > 0f && reserve < 1f) {
            float x = w * reserve;
            tick.setColor(TICK);
            canvas.drawRect(x - dp(1), dp(1.5f), x + dp(1), h - dp(1.5f), tick);
        }
    }

    float dp(float v) {
        return v * getResources().getDisplayMetrics().density;
    }
}