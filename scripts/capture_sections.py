#!/usr/bin/env python3
"""Capture individual dashboard sections for the trap-house portfolio."""
import os, time
from playwright.sync_api import sync_playwright

OUT = os.path.expanduser("~/projects/trap-house/docs/img")
os.makedirs(OUT, exist_ok=True)

with sync_playwright() as p:
    browser = p.chromium.launch(headless=True)
    context = browser.new_context(viewport={"width": 1920, "height": 1080})
    page = context.new_page()

    print("Loading frontend at localhost:8001...")
    page.goto("http://localhost:8001", wait_until="networkidle", timeout=30000)
    page.wait_for_timeout(5000)  # extra time for Leaflet tiles + data fetch

    # 1. Stats bar + Attack Map (top of page)
    print("1. Capturing attack-map.png...")
    el = page.query_selector("#panel-map")
    if el:
        el.screenshot(path=f"{OUT}/attack-map.png")
        print("   done")
    else:
        page.screenshot(path=f"{OUT}/attack-map.png")
        print("   (full page fallback)")

    # 2. MITRE Heatmap
    print("2. Capturing mitre-heatmap.png...")
    el = page.query_selector("#panel-heatmap")
    if el:
        el.screenshot(path=f"{OUT}/mitre-heatmap.png")
        print("   done")

    # 3. Attack Timeline
    print("3. Capturing attack-timeline.png...")
    el = page.query_selector("#panel-timeline")
    if el:
        el.screenshot(path=f"{OUT}/attack-timeline.png")
        print("   done")

    # 4. Top Attackers
    print("4. Capturing top-attackers.png...")
    el = page.query_selector("#panel-attackers")
    if el:
        el.screenshot(path=f"{OUT}/top-attackers.png")
        print("   done")

    # 5. Full dashboard (all sections)
    print("5. Capturing dashboard-full.png...")
    page.screenshot(path=f"{OUT}/dashboard-full.png", full_page=True)
    print("   done")

    # 6. Session Replay - select the Outlaw session (130.12.180.51)
    print("6. Selecting Outlaw session for replay...")
    select = page.query_selector("#session-select")
    if select:
        options = select.query_selector_all("option")
        outlaw_option = None
        for opt in options:
            text = opt.text_content() or ""
            if "130.12.180.51" in text:
                outlaw_option = opt
                print(f"   Found: {text.strip()[:80]}")
                break
        
        if outlaw_option:
            val = outlaw_option.get_attribute("value")
            select.select_option(value=val)
            page.wait_for_timeout(3000)  # wait for replay to render
            
            el = page.query_selector("#panel-replay")
            if el:
                print("   Capturing session-replay-outlaw.png...")
                el.screenshot(path=f"{OUT}/session-replay-outlaw.png")
                print("   done")
            
            # Also capture the full page with replay loaded
            print("   Capturing dashboard-with-replay.png...")
            page.screenshot(path=f"{OUT}/dashboard-with-replay.png", full_page=True)
            print("   done")
        else:
            # Just grab the first session
            print("   Outlaw IP not found in sessions. Listing available sessions...")
            for opt in options[:10]:
                text = opt.text_content() or ""
                if text.strip():
                    print(f"   - {text.strip()[:80]}")
            if len(options) > 1:
                first_val = options[1].get_attribute("value")
                if first_val:
                    select.select_option(value=first_val)
                    page.wait_for_timeout(3000)
                    el = page.query_selector("#panel-replay")
                    if el:
                        el.screenshot(path=f"{OUT}/session-replay.png")
                        print("   Captured session-replay.png (first available session)")
    else:
        print("   No session selector found")

    # 7. Stats bar close-up
    print("7. Capturing stats-bar.png...")
    el = page.query_selector("#stats-bar")
    if el:
        el.screenshot(path=f"{OUT}/stats-bar.png")
        print("   done")

    browser.close()
    
    print("\n=== Captured files ===")
    for f in sorted(os.listdir(OUT)):
        if f.endswith('.png'):
            size = os.path.getsize(f"{OUT}/{f}")
            print(f"  {f}: {size:,} bytes")