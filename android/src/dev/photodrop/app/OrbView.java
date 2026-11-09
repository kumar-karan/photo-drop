package dev.photodrop.app;

import android.animation.ValueAnimator;
import android.content.Context;
import android.graphics.Typeface;
import android.graphics.drawable.GradientDrawable;
import android.util.AttributeSet;
import android.view.Gravity;
import android.view.MotionEvent;
import android.view.View;
import android.view.animation.AccelerateDecelerateInterpolator;
import android.widget.FrameLayout;
import android.widget.LinearLayout;
import android.widget.TextView;

/**
 * Large interactive switch orb for starting the server.
 */
public class OrbView extends FrameLayout {

    public enum Mode {
        STOPPED,
        STARTING
    }

    private final View haloView;
    private final FrameLayout circleView;
    private final View iconView;
    private final TextView tvTitle;
    private final TextView tvSub;

    private final GradientDrawable haloDrawable;
    private final GradientDrawable circleDrawable;
    private final GradientDrawable iconDrawable;

    private Mode currentMode = Mode.STOPPED;
    private ValueAnimator pulseAnimator;

    public OrbView(Context context) {
        this(context, null);
    }

    public OrbView(Context context, AttributeSet attrs) {
        this(context, attrs, 0);
    }

    public OrbView(Context context, AttributeSet attrs, int defStyleAttr) {
        super(context, attrs, defStyleAttr);

        int orbSize = dp(196);
        int haloInset = dp(12);

        // 1. Halo View (outer ring)
        haloView = new View(context);
        LayoutParams haloLp = new LayoutParams(orbSize + haloInset * 2, orbSize + haloInset * 2);
        haloLp.gravity = Gravity.CENTER;
        haloView.setLayoutParams(haloLp);

        haloDrawable = new GradientDrawable();
        haloDrawable.setShape(GradientDrawable.OVAL);
        haloDrawable.setStroke(dp(1.5f), 0xFFEDF0F2);
        haloDrawable.setColor(0x00000000);
        haloView.setBackground(haloDrawable);
        addView(haloView);

        // 2. Main Circle
        circleView = new FrameLayout(context);
        LayoutParams circleLp = new LayoutParams(orbSize, orbSize);
        circleLp.gravity = Gravity.CENTER;
        circleView.setLayoutParams(circleLp);

        circleDrawable = new GradientDrawable();
        circleDrawable.setShape(GradientDrawable.OVAL);
        circleDrawable.setColor(0xFFFFFFFF);
        circleDrawable.setStroke(dp(2.5f), 0xFFE2E5E8);
        circleView.setBackground(circleDrawable);

        // Content inside circle
        LinearLayout contentCol = new LinearLayout(context);
        contentCol.setOrientation(LinearLayout.VERTICAL);
        contentCol.setGravity(Gravity.CENTER);
        LayoutParams contentLp = new LayoutParams(LayoutParams.MATCH_PARENT, LayoutParams.MATCH_PARENT);
        contentCol.setLayoutParams(contentLp);

        // Status icon / dot
        iconView = new View(context);
        int iconSize = dp(18);
        LinearLayout.LayoutParams iconLp = new LinearLayout.LayoutParams(iconSize, iconSize);
        iconLp.bottomMargin = dp(10);
        iconView.setLayoutParams(iconLp);

        iconDrawable = new GradientDrawable();
        iconDrawable.setShape(GradientDrawable.OVAL);
        iconDrawable.setColor(0xFFB7BDC3);
        iconView.setBackground(iconDrawable);
        contentCol.addView(iconView);

        // Title
        tvTitle = new TextView(context);
        tvTitle.setTextSize(17f);
        tvTitle.setTypeface(Typeface.DEFAULT, Typeface.BOLD);
        tvTitle.setTextColor(0xFF111315);
        tvTitle.setGravity(Gravity.CENTER);
        contentCol.addView(tvTitle);

        // Subtitle
        tvSub = new TextView(context);
        tvSub.setTextSize(13f);
        tvSub.setTextColor(0xFF6C737B);
        tvSub.setGravity(Gravity.CENTER);
        LinearLayout.LayoutParams subLp = new LinearLayout.LayoutParams(
                LinearLayout.LayoutParams.WRAP_CONTENT,
                LinearLayout.LayoutParams.WRAP_CONTENT
        );
        subLp.topMargin = dp(4);
        tvSub.setLayoutParams(subLp);
        contentCol.addView(tvSub);

        circleView.addView(contentCol);
        addView(circleView);

        setMode(Mode.STOPPED);
    }

    public void setMode(Mode mode) {
        this.currentMode = mode;
        if (mode == Mode.STOPPED) {
            circleDrawable.setColor(0xFFFFFFFF);
            circleDrawable.setStroke(dp(2.5f), 0xFFE2E5E8);
            haloDrawable.setStroke(dp(1.5f), 0xFFEDF0F2);
            iconDrawable.setColor(0xFFB7BDC3);
            tvTitle.setText("Tap to start");
            tvTitle.setTextColor(0xFF111315);
            tvSub.setText("server is off");
            tvSub.setTextColor(0xFF6C737B);
            stopPulse();
        } else {
            circleDrawable.setColor(0xFFFDF2E3);
            circleDrawable.setStroke(dp(2.5f), 0xFFEFD3A6);
            haloDrawable.setStroke(dp(1.5f), 0xFFF6E3C4);
            iconDrawable.setColor(0xFFB26A00);
            tvTitle.setText("Starting");
            tvTitle.setTextColor(0xFF854D0E);
            tvSub.setText("about four seconds");
            tvSub.setTextColor(0xFF8A5A18);
            startPulse();
        }
    }

    private void startPulse() {
        if (pulseAnimator != null && pulseAnimator.isRunning()) return;
        pulseAnimator = ValueAnimator.ofFloat(1f, 1.15f, 1f);
        pulseAnimator.setDuration(1200);
        pulseAnimator.setRepeatCount(ValueAnimator.INFINITE);
        pulseAnimator.setInterpolator(new AccelerateDecelerateInterpolator());
        pulseAnimator.addUpdateListener(new ValueAnimator.AnimatorUpdateListener() {
            @Override
            public void onAnimationUpdate(ValueAnimator va) {
                float s = (Float) va.getAnimatedValue();
                haloView.setScaleX(s);
                haloView.setScaleY(s);
                iconView.setAlpha(s > 1.05f ? 0.6f : 1f);
            }
        });
        pulseAnimator.start();
    }

    private void stopPulse() {
        if (pulseAnimator != null) {
            pulseAnimator.cancel();
            pulseAnimator = null;
        }
        haloView.setScaleX(1f);
        haloView.setScaleY(1f);
        iconView.setAlpha(1f);
    }

    @Override
    public boolean onTouchEvent(MotionEvent event) {
        if (!isEnabled()) return super.onTouchEvent(event);
        switch (event.getAction()) {
            case MotionEvent.ACTION_DOWN:
                circleView.animate().scaleX(0.96f).scaleY(0.96f).setDuration(100).start();
                break;
            case MotionEvent.ACTION_UP:
            case MotionEvent.ACTION_CANCEL:
                circleView.animate().scaleX(1.0f).scaleY(1.0f).setDuration(150).start();
                break;
        }
        return super.onTouchEvent(event);
    }

    @Override
    protected void onDetachedFromWindow() {
        super.onDetachedFromWindow();
        stopPulse();
    }

    private int dp(float v) {
        return Math.round(v * getResources().getDisplayMetrics().density);
    }
}
