#!/usr/bin/env python3
"""
Trap House: Outlaw/RedTail Kill Chain Animation
Manim CE script for a 30-second portfolio animation showing the full
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

class OutlawKillChain(Scene):
    def construct(self):
        self.camera.background_color = BG

        # === SCENE 1: TITLE ===
        title = Text("Outlaw/RedTail Kill Chain", font_size=42, color=PRIMARY, weight=BOLD, font=MONO)
        subtitle = Text("130.12.180.51 (Saudi Arabia) vs Trap House Honeypot", font_size=22, color=DIM, font=MONO)
        subtitle.next_to(title, DOWN, buff=0.4)
        
        self.play(Write(title), run_time=1.5)
        self.play(FadeIn(subtitle), run_time=0.8)
        self.wait(1.5)
        self.play(FadeOut(Group(title, subtitle)), run_time=0.5)

        # === SCENE 2: KILL CHAIN STEPS ===
        # Define the 5 kill chain steps
        steps = [
            ("T1110.001", "Brute Force", "Hammered root passwords", ACCENT),
            ("T1082", "System Info Discovery", "uname -s -m (arch fingerprint)", PRIMARY),
            ("T1105", "Ingress Tool Transfer", "SFTP upload: 6 files, 8 times", SECONDARY),
            ("Persistence", "SSH Key + chattr +ai", "rsa-key-20230629 (Outlaw sig)", DANGER),
            ("T1059", "Execution", "clean.sh + setup.sh + redtail binary", ACCENT),
        ]

        # Build the chain as a vertical flow
        chain_group = VGroup()
        
        for i, (tcode, name, detail, color) in enumerate(steps):
            # Step number badge
            num = Text(f"{i+1}", font_size=28, color=color, weight=BOLD, font=MONO)
            num_badge = Circle(radius=0.35, color=color, fill_opacity=0.15)
            num.move_to(num_badge.get_center())
            num_group = VGroup(num_badge, num)
            
            # MITRE technique code
            tcode_text = Text(tcode, font_size=22, color=color, weight=BOLD, font=MONO)
            
            # Step name
            name_text = Text(name, font_size=26, color=WHITE, font=MONO)
            
            # Detail
            detail_text = Text(detail, font_size=18, color=DIM, font=MONO)
            
            # Group the text items
            text_group = VGroup(tcode_text, name_text, detail_text)
            text_group.arrange(RIGHT, buff=0.3)
            
            # Combine number + text
            step_row = VGroup(num_group, text_group)
            step_row.arrange(RIGHT, buff=0.4)
            
            chain_group.add(step_row)
        
        chain_group.arrange(DOWN, buff=0.6)
        chain_group.move_to(ORIGIN)
        
        # Add connecting lines between steps
        lines = VGroup()
        for i in range(len(chain_group) - 1):
            top = chain_group[i].get_bottom()
            bottom = chain_group[i+1].get_top()
            line = DashedLine(top, bottom, color=DIM, stroke_width=2)
            lines.add(line)
        
        # Animate each step appearing in sequence
        for i, (step_row, line) in enumerate(zip(chain_group, lines)):
            tcode, name, detail, color = steps[i]
            
            self.play(FadeIn(step_row, shift=RIGHT * 0.3), run_time=0.8)
            self.play(Create(line), run_time=0.3)
            self.wait(0.5)
        
        # Last step has no line after it
        self.play(FadeIn(chain_group[-1], shift=RIGHT * 0.3), run_time=0.8)
        self.wait(1.0)
        
        # === SCENE 3: HIGHLIGHT THE DETECTION ===
        # Fade everything dim, then show a detection banner
        self.play(
            chain_group.animate.set_opacity(0.3),
            lines.animate.set_opacity(0.15),
            run_time=0.5
        )
        
        detected = Text("DETECTED BY HONEYPOT", font_size=36, color=DANGER, weight=BOLD, font=MONO)
        detected.to_edge(DOWN, buff=1.0)
        
        banner_bg = SurroundingRectangle(
            detected, color=DANGER, fill_color=DANGER, fill_opacity=0.1, buff=0.2
        )
        
        self.play(Write(detected), Create(banner_bg), run_time=1.5)
        self.wait(1.0)
        
        # === SCENE 4: KEY STATS ===
        self.play(FadeOut(Group(chain_group, lines, detected, banner_bg)), run_time=0.5)
        
        stats_title = Text("Campaign Impact", font_size=36, color=PRIMARY, weight=BOLD, font=MONO)
        stats_title.to_edge(UP, buff=1.0)
        self.play(Write(stats_title), run_time=1.0)
        
        stats = [
            ("162 events", "from a single IP"),
            ("18 sessions", "over 8 days"),
            ("6 files uploaded", "sha256 verified"),
            ("37/64 VirusTotal", "redtail.x86_64"),
            ("ThreatFox IOC 1820703", "elf.redtail, confidence 85%"),
        ]
        
        stats_group = VGroup()
        for stat_value, stat_label in stats:
            val = Text(stat_value, font_size=24, color=ACCENT, weight=BOLD, font=MONO)
            label = Text(stat_label, font_size=18, color=DIM, font=MONO)
            row = VGroup(val, label)
            row.arrange(RIGHT, buff=0.3)
            stats_group.add(row)
        
        stats_group.arrange(DOWN, buff=0.4, aligned_edge=LEFT)
        stats_group.next_to(stats_title, DOWN, buff=0.8)
        
        for row in stats_group:
            self.play(FadeIn(row, shift=RIGHT * 0.2), run_time=0.5)
            self.wait(0.3)
        
        self.wait(2.0)
        
        # === SCENE 5: CLOSING ===
        self.play(FadeOut(Group(stats_title, stats_group)), run_time=0.5)
        
        closing = Text("Trap House Deception Honeypot", font_size=32, color=PRIMARY, weight=BOLD, font=MONO)
        closing_sub = Text("Detection and intelligence. No offensive capability.", font_size=18, color=DIM, font=MONO)
        closing_sub.next_to(closing, DOWN, buff=0.3)
        
        self.play(Write(closing), run_time=1.0)
        self.play(FadeIn(closing_sub), run_time=0.8)
        self.wait(2.0)
        
        self.play(FadeOut(Group(closing, closing_sub)), run_time=0.8)