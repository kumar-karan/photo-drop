package dev.photodrop.app;

import android.animation.ArgbEvaluator;
import android.animation.ValueAnimator;
import android.content.Context;
import android.graphics.Color;
import android.graphics.Typeface;
import android.graphics.drawable.GradientDrawable;
import android.util.AttributeSet;
import android.view.Gravity;
import android.view.View;
import android.view.animation.AccelerateDecelerateInterpolator;
import android.widget.FrameLayout;
import android.widget.LinearLayout;
import android.widget.TextView;

/**
 * Top pinned status band representing the server's live connectivity state.
 */
public class StatusStripView extends LinearLayout {

    public enum State {
        STOPPED(0xFFECEEF0, 0xFF8B9199, 0xFF3A4046, 0xFF5E656D, 0xFF3A4046, 0xFFE2E5E8, "STOPPED", false),
        STARTING(0xFFFDF2E3, 0xFFB26A00, 0xFF854D0E, 0xFF8A5A18, 0xFF854D0E, 0xFFF6E3C4, "WAIT", true),
        ONLINE_LOCAL(0xFFEAF5EC, 0xFF167A38, 0xFF0E5224, 0xFF1C6B39, 0xFF0E5224, 0xFFD7EBDC, "ON THIS WI-FI", false),
        ONLINE_TUNNEL(0xFF167A38, 0xFF7BE3A6, 0xFFFFFFFF, 0xFFDCF5E8, 0xFF0E5224, 0xFFFFFFFF, "LIVE", true),
        STORAGE_LOW(0xFFFCEDEC, 0xFFB3261E, 0xFF8C1D18, 0xFF9A4038, 0xFF8C1D18, 0xFFF3D6D3, "PAUSED", false),
        TERMUX_ERROR(0xFF212529, 0xFFFF8A80, 0xFFFFFFFF, 0xFFC7CCD1, 0xFF212529, 0xFFFFFFFF, "BLOCKED", false);

        public final int bg;
        public final int dotColor;
        public final int titleColor;
        public final int subColor;
        public final int pillTextColor;
        public final int pillBgColor;
        public final String pillLabel;
        public final boolean pulse;

        State(int bg, int dot, int title, int sub, int pText, int pBg, String label, boolean pulse) {
            this.bg = bg;
            this.dotColor = dot;
            this.titleColor = title;
            this.subColor = sub;
            this.pillTextColor = pText;
            this.pillBgColor = pBg;
            this.pillLabel = label;
            this.pulse = pulse;
        }
    }

    private final View dotView;
    private final TextView tvTitle;
    private final TextView tvSub;
    private final TextView tvPill;
    private final GradientDrawable dotDrawable;
    private final GradientDrawable pillDrawable;

    private State currentState = State.STOPPED;
    private ValueAnimator colorAnimator;
    private ValueAnimator pulseAnimator;

    public StatusStripView(Context context) {
        this(context, null);
    }

    public StatusStripView(Context context, AttributeSet attrs) {
        this(context, attrs, 0);
    }

    public StatusStripView(Context context, AttributeSet attrs, int defStyleAttr) {
        super(context, attrs, defStyleAttr);

        setOrientation(HORIZONTAL);
        setGravity(Gravity.CENTER_VERTICAL);
        int padH = dp(20);
        int padV = dp(14);
        setPadding(padH, padV, padH, padV);
        setMinimumHeight(dp(64));

        // 1. Status Dot
        dotView = new View(context);
        int dotSize = dp(10);
        LayoutParams dotLp = new LayoutParams(dotSize, dotSize);
        dotLp.rightMargin = dp(12);
        dotLp.gravity = Gravity.CENTER_VERTICAL;
        dotView.setLayoutParams(dotLp);

        dotDrawable = new GradientDrawable();
        dotDrawable.setShape(GradientDrawable.OVAL);
        dotDrawable.setColor(currentState.dotColor);
        dotView.setBackground(dotDrawable);
        addView(dotView);

        // 2. Titles Container
        LinearLayout textCol = new LinearLayout(context);
        textCol.setOrientation(VERTICAL);
        LayoutParams textColLp = new LayoutParams(0, LayoutParams.WRAP_CONTENT, 1f);
        textCol.setLayoutParams(textColLp);

        tvTitle = new TextView(context);
        tvTitle.setTextSize(14.5f);
        tvTitle.setTypeface(Typeface.DEFAULT, Typeface.BOLD);
        tvTitle.setSingleLine(true);
        textCol.addView(tvTitle);

        tvSub = new TextView(context);
        tvSub.setTextSize(12f);
        tvSub.setSingleLine(true);
        LayoutParams subLp = new LayoutParams(LayoutParams.WRAP_CONTENT, LayoutParams.WRAP_CONTENT);
        subLp.topMargin = dp(2);
        tvSub.setLayoutParams(subLp);
        textCol.addView(tvSub);

        addView(textCol);

        // 3. State Pill
        tvPill = new TextView(context);
        tvPill.setTextSize(10.5f);
        tvPill.setTypeface(Typeface.DEFAULT, Typeface.BOLD);
        tvPill.setLetterSpacing(0.04f);
        int pillPadH = dp(9);
        int pillPadV = dp(4);
        tvPill.setPadding(pillPadH, pillPadV, pillPadH, pillPadV);

        pillDrawable = new GradientDrawable();
        pillDrawable.setShape(GradientDrawable.RECTANGLE);
        pillDrawable.setCornerRadius(dp(12));
        tvPill.setBackground(pillDrawable);

        LayoutParams pillLp = new LayoutParams(LayoutParams.WRAP_CONTENT, LayoutParams.WRAP_CONTENT);
        pillLp.leftMargin = dp(10);
        pillLp.gravity = Gravity.CENTER_VERTICAL;
        tvPill.setLayoutParams(pillLp);
        addView(tvPill);

        applyStateDirect(currentState);
    }

    public void setState(State state, String title, String subtitle) {
        if (state == null) return;
        boolean stateChanged = this.currentState != state;
        State prev = this.currentState;
        this.currentState = state;

        tvTitle.setText(title);
        tvSub.setText(subtitle);
        tvPill.setText(state.pillLabel);

        if (stateChanged) {
            animateStateTransition(prev, state);
        }

        updatePulse(state.pulse);
    }

    private void applyStateDirect(State s) {
        setBackgroundColor(s.bg);
        dotDrawable.setColor(s.dotColor);
        tvTitle.setTextColor(s.titleColor);
        tvSub.setTextColor(s.subColor);
        tvPill.setTextColor(s.pillTextColor);
        pillDrawable.setColor(s.pillBgColor);
    }

    private void animateStateTransition(final State from, final State to) {
        if (colorAnimator != null && colorAnimator.isRunning()) {
            colorAnimator.cancel();
        }

        final ArgbEvaluator evaluator = new ArgbEvaluator();
        colorAnimator = ValueAnimator.ofFloat(0f, 1f);
        colorAnimator.setDuration(220);
        colorAnimator.setInterpolator(new AccelerateDecelerateInterpolator());
        colorAnimator.addUpdateListener(new ValueAnimator.AnimatorUpdateListener() {
            @Override
            public void onAnimationUpdate(ValueAnimator va) {
                float f = (Float) va.getAnimatedValue();
                int curBg = (Integer) evaluator.evaluate(f, from.bg, to.bg);
                int curDot = (Integer) evaluator.evaluate(f, from.dotColor, to.dotColor);
                int curTitle = (Integer) evaluator.evaluate(f, from.titleColor, to.titleColor);
                int curSub = (Integer) evaluator.evaluate(f, from.subColor, to.subColor);
                int curPillText = (Integer) evaluator.evaluate(f, from.pillTextColor, to.pillTextColor);
                int curPillBg = (Integer) evaluator.evaluate(f, from.pillBgColor, to.pillBgColor);

                setBackgroundColor(curBg);
                dotDrawable.setColor(curDot);
                tvTitle.setTextColor(curTitle);
                tvSub.setTextColor(curSub);
                tvPill.setTextColor(curPillText);
                pillDrawable.setColor(curPillBg);
            }
        });
        colorAnimator.start();
    }

    private void updatePulse(boolean enable) {
        if (!enable) {
            if (pulseAnimator != null) {
                pulseAnimator.cancel();
                pulseAnimator = null;
            }
            dotView.setScaleX(1f);
            dotView.setScaleY(1f);
            dotView.setAlpha(1f);
            return;
        }

        if (pulseAnimator != null && pulseAnimator.isRunning()) return;

        pulseAnimator = ValueAnimator.ofFloat(1f, 0.45f, 1f);
        pulseAnimator.setDuration(currentState == State.STARTING ? 1100 : 2200);
        pulseAnimator.setRepeatCount(ValueAnimator.INFINITE);
        pulseAnimator.setInterpolator(new AccelerateDecelerateInterpolator());
        pulseAnimator.addUpdateListener(new ValueAnimator.AnimatorUpdateListener() {
            @Override
            public void onAnimationUpdate(ValueAnimator va) {
                float val = (Float) va.getAnimatedValue();
                dotView.setScaleX(0.85f + 0.15f * val);
                dotView.setScaleY(0.85f + 0.15f * val);
                dotView.setAlpha(val);
            }
        });
        pulseAnimator.start();
    }

    @Override
    protected void onDetachedFromWindow() {
        super.onDetachedFromWindow();
        if (colorAnimator != null) colorAnimator.cancel();
        if (pulseAnimator != null) pulseAnimator.cancel();
    }

    private int dp(float v) {
        return Math.round(v * getResources().getDisplayMetrics().density);
    }
}
