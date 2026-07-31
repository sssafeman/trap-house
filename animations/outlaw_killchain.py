#!/usr/bin/env python3
"""
Trap House: Outlaw/RedTail Kill Chain Animation
Manim CE script for a cinematic SOC-dashboard animation showing the full
attacker kill chain from 130.12.180.51, mapped to MITRE ATT&CK techniques.

Render: manim -ql outlaw_killchain.py OutlawKillChain  (draft)
        manim -qh outlaw_killchain.py OutlawKillChain  (production)
"""

from manim import *

# Neon tech palette (dark SOC dashboard aesthetic)
BG = "#0A0A0A"
PRIMARY = "#00F5FF"     # cyan: main flow
SECONDARY = "#FF00FF"   # magenta: attacker
ACCENT = "#39FF14"      # green: success/compromise
DANGER = "#FF4444"      # red: detection alert
DIM = "#333333"         # dim gray: context
WHITE = "#EAEAEA"
MONO = "Menlo"

# Opacity layers: primary content, contextual content, structural elements
OP_PRIMARY = 1.0
OP_CONTEXT = 0.4
OP_STRUCT = 0.15


def typewriter(text: Text, target_opacity: float = 1.0, run_time: float = 0.8) -> UpdateFromAlphaFunc:
    """Reveal a Text mobject glyph by glyph, left to right, up to target_opacity."""
    n_glyphs = len(text)
    for glyph in text:
        glyph.set_opacity(0)

    def reveal(mob: Text, alpha: float) -> None:
        reveal_count = int(alpha * n_glyphs)
        for j, glyph in enumerate(mob):
            glyph.set_opacity(target_opacity if j < reveal_count else 0)

    return UpdateFromAlphaFunc(text, reveal, run_time=run_time, rate_func=linear)


def digit_glyphs(text_mob: Text, source: str, number: str) -> VGroup:
    """Return the glyphs of text_mob that render the given numeric substring.

    Glyph indices skip spaces, and Pango can merge letter pairs like fi into
    one ligature glyph, so the slice is computed from whichever end of the
    string is closest to the number. Digits never ligate, and nothing between
    the number and that end can shift the offsets.
    """
    stripped = source.replace(" ", "")
    start = stripped.index(number)
    if start == 0:
        return text_mob[0:len(number)]
    trailing = len(stripped) - start - len(number)
    end = len(text_mob) - trailing
    return text_mob[end - len(number):end]


def make_counter(
    tracker: ValueTracker,
    anchor: np.ndarray,
    font_size: float,
    color: str,
    weight: str,
    opacity: float,
) -> Mobject:
    """Build an always_redraw mono-font integer counter, right-aligned at anchor."""

    def build() -> Text:
        num = Text(
            str(int(round(tracker.get_value()))),
            font=MONO, font_size=font_size, color=color, weight=weight,
        )
        num.set_opacity(opacity)
        num.move_to(anchor, aligned_edge=RIGHT)
        return num

    return always_redraw(build)


class OutlawKillChain(MovingCameraScene):
    def construct(self) -> None:
        self.camera.background_color = BG
        frame = self.camera.frame
        frame.save_state()

        # === SCENE 1: TITLE ===
        title = Text("Outlaw/RedTail Kill Chain", font_size=42, color=PRIMARY, weight=BOLD, font=MONO)
        subtitle = Text("130.12.180.51 (Saudi Arabia) vs Trap House Honeypot", font_size=22, color=WHITE, font=MONO)
        subtitle.set_opacity(OP_CONTEXT)
        subtitle.next_to(title, DOWN, buff=0.4)

        self.play(Write(title), run_time=1.4, rate_func=smooth)
        self.play(FadeIn(subtitle, shift=UP * 0.15), run_time=0.7, rate_func=smooth)
        self.wait(1.2)
        self.play(FadeOut(title, shift=UP * 0.2), FadeOut(subtitle), run_time=0.5, rate_func=smooth)

        # === SCENE 2: KILL CHAIN STEPS (camera pans down the chain) ===
        steps = [
            ("T1110.001", "Brute Force", "Hammered root passwords", ACCENT),
            ("T1082", "System Info Discovery", "uname -s -m (arch fingerprint)", PRIMARY),
            ("T1105", "Ingress Tool Transfer", "SFTP upload: 7 filenames, 423 total uploads", SECONDARY),
            ("Persistence", "SSH Key + chattr +ai", "rsa-key-20230629 (Outlaw sig)", DANGER),
            ("T1059", "Execution", "clean.sh + setup.sh + redtail binary", ACCENT),
        ]

        chain_group = VGroup()
        for i, (tcode, name, detail, color) in enumerate(steps):
            num = Text(str(i + 1), font_size=28, color=color, weight=BOLD, font=MONO)
            num_badge = Circle(radius=0.35, color=color, fill_color=color, fill_opacity=OP_STRUCT)
            num_badge.set_stroke(opacity=0.4)
            num.move_to(num_badge.get_center())
            num_group = VGroup(num_badge, num)

            tcode_text = Text(tcode, font_size=22, color=color, weight=BOLD, font=MONO)
            name_text = Text(name, font_size=26, color=WHITE, font=MONO)
            detail_text = Text(detail, font_size=18, color=WHITE, font=MONO)

            text_group = VGroup(tcode_text, name_text, detail_text)
            text_group.arrange(RIGHT, buff=0.3)

            step_row = VGroup(num_group, text_group)
            step_row.arrange(RIGHT, buff=0.4)
            chain_group.add(step_row)

        # Taller than one camera frame so the pan has somewhere to go
        chain_group.arrange(DOWN, buff=1.1)
        chain_group.move_to(ORIGIN)

        lines = VGroup()
        for i in range(len(chain_group) - 1):
            line = DashedLine(
                chain_group[i].get_bottom(), chain_group[i + 1].get_top(),
                color=WHITE, stroke_width=2,
            )
            line.set_stroke(opacity=OP_STRUCT)
            lines.add(line)

        # Camera starts tight on step 1, slightly above, then follows the chain down
        frame.set(height=6.0)
        frame.move_to(np.array([0.0, chain_group[0].get_center()[1] + 0.3, 0.0]))

        for i, step_row in enumerate(chain_group):
            num_group, text_group = step_row
            tcode_text, name_text, detail_text = text_group
            cam_target = np.array([0.0, step_row.get_center()[1] - 0.35, 0.0])

            reveal = LaggedStart(
                GrowFromCenter(num_group, rate_func=smooth),
                Write(tcode_text, rate_func=smooth),
                FadeIn(name_text, shift=RIGHT * 0.25, rate_func=smooth),
                lag_ratio=0.35,
            )
            self.play(
                frame.animate(rate_func=smooth).move_to(cam_target),
                reveal,
                run_time=0.9 + 0.15 * (i % 2),
            )
            self.play(typewriter(detail_text, OP_CONTEXT, run_time=0.6 + 0.06 * i))
            if i < len(lines):
                self.play(Create(lines[i]), run_time=0.35, rate_func=smooth)
            self.wait(0.15 + 0.1 * ((i + 1) % 2))

        self.wait(0.8)

        # === SCENE 3: DETECTION BANNER (pulsing alert) ===
        detected = Text("DETECTED BY HONEYPOT", font_size=36, color=DANGER, weight=BOLD, font=MONO)
        detected.next_to(chain_group, DOWN, buff=0.9)
        banner_bg = SurroundingRectangle(
            detected, color=DANGER, fill_color=DANGER, fill_opacity=0.1, buff=0.2
        )

        cam_target = np.array([0.0, banner_bg.get_center()[1] + 1.6, 0.0])
        self.play(
            chain_group.animate.set_opacity(0.2),
            lines.animate.set_opacity(0.1),
            frame.animate.move_to(cam_target),
            run_time=0.9, rate_func=smooth,
        )
        self.play(Write(detected), Create(banner_bg), run_time=1.1, rate_func=smooth)

        # Pulse on a beat: stroke width, fill brightness, subtle scale
        for _ in range(3):
            self.play(
                banner_bg.animate.set_stroke(width=8).set_fill(opacity=0.3).scale(1.04),
                detected.animate.scale(1.04),
                rate_func=there_and_back,
                run_time=0.5,
            )
        self.wait(0.5)

        # === SCENE 4: KEY STATS (count-up dashboard) ===
        self.play(FadeOut(VGroup(chain_group, lines, detected, banner_bg)), run_time=0.6, rate_func=smooth)
        frame.restore()

        stats_title = Text("Campaign Impact", font_size=36, color=PRIMARY, weight=BOLD, font=MONO)
        stats_title.to_edge(UP, buff=1.0)
        self.play(Write(stats_title), run_time=0.9, rate_func=smooth)

        stats = [
            ("992 events", "from a single source"),
            ("75 sessions", "over 31 days"),
            ("423 uploads", "across 7 filenames"),
            ("37 SHA256 values", "across captured variants"),
            ("65 dropper sequences", "with SSH key persistence"),
        ]

        stats_group = VGroup()
        for stat_value, stat_label in stats:
            val = Text(stat_value, font_size=24, color=ACCENT, weight=BOLD, font=MONO)
            label = Text(stat_label, font_size=18, color=WHITE, font=MONO)
            label.set_opacity(OP_CONTEXT)
            row = VGroup(val, label)
            row.arrange(RIGHT, buff=0.3)
            stats_group.add(row)

        stats_group.arrange(DOWN, buff=0.4, aligned_edge=LEFT)
        stats_group.next_to(stats_title, DOWN, buff=0.8)

        # Counted values: hide the final digit glyphs, overlay live counters
        # right-aligned where those glyphs sit. The labels stay static.
        counter_specs = [
            (stats_group[0][0], stats[0][0], "992", 992, 24, ACCENT, BOLD, OP_PRIMARY),
            (stats_group[1][0], stats[1][0], "75", 75, 24, ACCENT, BOLD, OP_PRIMARY),
            (stats_group[2][0], stats[2][0], "423", 423, 24, ACCENT, BOLD, OP_PRIMARY),
            (stats_group[3][0], stats[3][0], "37", 37, 24, ACCENT, BOLD, OP_PRIMARY),
            (stats_group[4][0], stats[4][0], "65", 65, 24, ACCENT, BOLD, OP_PRIMARY),
        ]

        trackers = []
        counters = []
        swaps = []
        for text_mob, source, number, final, fsize, color, weight, opacity in counter_specs:
            glyphs = digit_glyphs(text_mob, source, number)
            anchor = glyphs.get_right().copy()
            glyphs.set_opacity(0)
            tracker = ValueTracker(0)
            counter = make_counter(tracker, anchor, fsize, color, weight, opacity)
            trackers.append((tracker, final))
            counters.append(counter)
            swaps.append((glyphs, opacity, counter))

        self.play(
            LaggedStart(
                *[FadeIn(row, shift=RIGHT * 0.25, rate_func=smooth) for row in stats_group],
                lag_ratio=0.18,
            ),
            run_time=1.8,
        )

        self.add(*counters)
        self.play(
            LaggedStart(
                *[
                    tracker.animate(run_time=1.5, rate_func=smooth).set_value(final)
                    for tracker, final in trackers
                ],
                lag_ratio=0.25,
            )
        )

        # Swap live counters back to the static glyphs (pixel-identical)
        for glyphs, opacity, counter in swaps:
            glyphs.set_opacity(opacity)
            self.remove(counter)

        self.wait(1.6)

        # === SCENE 5: CLOSING ===
        self.play(FadeOut(VGroup(stats_title, stats_group)), run_time=0.5, rate_func=smooth)

        closing = Text("Trap House Deception Honeypot", font_size=32, color=PRIMARY, weight=BOLD, font=MONO)
        closing_sub = Text("Detection and intelligence. No offensive capability.", font_size=18, color=WHITE, font=MONO)
        closing_sub.set_opacity(OP_CONTEXT)
        closing_sub.next_to(closing, DOWN, buff=0.3)

        self.play(Write(closing), run_time=1.0, rate_func=smooth)
        self.play(FadeIn(closing_sub, shift=UP * 0.1), run_time=0.7, rate_func=smooth)
        self.wait(2.0)
        self.play(FadeOut(VGroup(closing, closing_sub)), run_time=0.8, rate_func=smooth)
