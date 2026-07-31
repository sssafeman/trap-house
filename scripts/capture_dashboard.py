#!/usr/bin/env python3
"""Capture the portfolio dashboard sections and the Outlaw replay."""
from __future__ import annotations

import os
from pathlib import Path

from playwright.sync_api import sync_playwright

BASE_URL = os.environ.get("TRAP_HOUSE_URL", "http://localhost:8001")
TARGET_IP = os.environ.get("TRAP_HOUSE_REPLAY_IP", "130.12.180.51")
TARGET_SESSION = os.environ.get("TRAP_HOUSE_REPLAY_SESSION", "")
OUTPUT_DIR = Path(
    os.environ.get(
        "TRAP_HOUSE_CAPTURE_DIR",
        str(Path(__file__).resolve().parents[1] / "docs" / "img"),
    )
)
OUTPUT_DIR.mkdir(parents=True, exist_ok=True)


def capture_selector(page, selector: str, filename: str) -> None:
    element = page.locator(selector)
    if element.count() == 0:
        print(f"Skipping {filename}: {selector} was not found")
        return
    element.first.screenshot(path=str(OUTPUT_DIR / filename))
    print(f"Captured {filename}")


with sync_playwright() as playwright:
    browser = playwright.chromium.launch(headless=True)
    context = browser.new_context(viewport={"width": 1920, "height": 1080})
    page = context.new_page()

    print(f"Loading dashboard at {BASE_URL}")
    page.goto(BASE_URL, wait_until="networkidle", timeout=30_000)
    page.wait_for_timeout(5_000)

    capture_selector(page, "#panel-map", "attack-map.png")
    capture_selector(page, "#panel-heatmap", "mitre-heatmap.png")
    capture_selector(page, "#panel-timeline", "attack-timeline.png")
    capture_selector(page, "#panel-attackers", "top-attackers.png")
    capture_selector(page, "#stats-bar", "stats-bar.png")

    # Disable the sticky header only while creating a full-page artifact.
    page.add_style_tag(content=".hud-bar { position: relative !important; }")
    page.screenshot(path=str(OUTPUT_DIR / "dashboard-full.png"), full_page=True)
    print("Captured dashboard-full.png")

    session_select = page.locator("#session-select")
    if session_select.count() > 0:
        target_value = TARGET_SESSION or None
        if TARGET_SESSION:
            session_select.evaluate(
                """(select, value) => {
                    const option = document.createElement('option');
                    option.value = value;
                    option.textContent = `${value} | configured replay session`;
                    select.appendChild(option);
                }""",
                TARGET_SESSION,
            )
        else:
            for option in session_select.locator("option").all():
                if TARGET_IP in (option.text_content() or ""):
                    target_value = option.get_attribute("value")
                    break

        if target_value:
            session_select.select_option(value=target_value)
            page.wait_for_timeout(3_000)
            capture_selector(page, "#panel-replay", "session-replay-outlaw.png")
            page.screenshot(
                path=str(OUTPUT_DIR / "dashboard-full-with-outlaw-replay.png"),
                full_page=True,
            )
            print("Captured dashboard-full-with-outlaw-replay.png")
        else:
            print(f"Skipping replay: no session matched {TARGET_IP}")
    else:
        print("Skipping replay: #session-select was not found")

    browser.close()

print(f"Dashboard artifacts written to {OUTPUT_DIR}")
