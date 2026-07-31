#!/usr/bin/env python3
"""Force-load the Outlaw session replay and capture it."""
import os
from playwright.sync_api import sync_playwright

OUT = os.path.expanduser("~/projects/trap-house/docs/img")

# Outlaw session with 14 events
OUTLAW_SESSION = "324b12281c8d"

with sync_playwright() as p:
    browser = p.chromium.launch(headless=True)
    context = browser.new_context(viewport={"width": 1920, "height": 1080})
    page = context.new_page()

    print("Loading frontend at localhost:8001...")
    page.goto("http://localhost:8001", wait_until="networkidle", timeout=30000)
    page.wait_for_timeout(5000)

    # Inject the Outlaw session into the dropdown and select it
    print(f"Injecting Outlaw session {OUTLAW_SESSION}...")
    page.evaluate(f"""
    (() => {{
        const sel = document.getElementById('session-select');
        if (!sel) return 'no select found';
        
        // Add the Outlaw session option
        const opt = document.createElement('option');
        opt.value = '{OUTLAW_SESSION}';
        opt.textContent = '{OUTLAW_SESSION} | 130.12.180.51 | 14 ev (Outlaw/RedTail)';
        sel.appendChild(opt);
        
        // Select it
        sel.value = '{OUTLAW_SESSION}';
        
        // Dispatch change event to trigger the frontend's event handler
        sel.dispatchEvent(new Event('change', {{ bubbles: true }}));
        
        return 'injected and selected';
    }})()
    """)
    
    # Wait for the replay to fetch and render
    print("Waiting for replay to render...")
    page.wait_for_timeout(5000)

    # Check if the replay panel has content
    replay_content = page.query_selector("#session-replay")
    if replay_content:
        text = replay_content.text_content() or ""
        print(f"Replay panel text: {text[:200]}")

    # Capture the replay panel
    print("Capturing session-replay-outlaw.png...")
    el = page.query_selector("#panel-replay")
    if el:
        el.screenshot(path=f"{OUT}/session-replay-outlaw.png")
        print("done")

    # Capture the full page with the Outlaw replay
    print("Capturing dashboard-full-with-outlaw-replay.png...")
    page.add_style_tag(content=".topnav { position: static !important; }")
    page.screenshot(path=f"{OUT}/dashboard-full-with-outlaw-replay.png", full_page=True)
    print("done")

    browser.close()
    
    print("\n=== Files ===")
    for f in sorted(os.listdir(OUT)):
        if f.endswith('.png'):
            size = os.path.getsize(f"{OUT}/{f}")
            print(f"  {f}: {size:,} bytes")