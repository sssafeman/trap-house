#!/usr/bin/env python3
"""Capture the Outlaw session replay and refined dashboard screenshots."""
import os, time
from playwright.sync_api import sync_playwright

OUT = os.path.expanduser("~/projects/trap-house/docs/img")

with sync_playwright() as p:
    browser = p.chromium.launch(headless=True)
    context = browser.new_context(viewport={"width": 1920, "height": 1080})
    page = context.new_page()

    print("Loading frontend at localhost:8001...")
    page.goto("http://localhost:8001", wait_until="networkidle", timeout=30000)
    page.wait_for_timeout(5000)

    # Check the session dropdown for Outlaw sessions
    select = page.query_selector("#session-select")
    if select:
        options = select.query_selector_all("option")
        print(f"Total options in dropdown: {len(options)}")
        
        # Find all options that contain 130.12.180.51
        outlaw_options = []
        for opt in options:
            text = opt.text_content() or ""
            if "130.12.180.51" in text:
                outlaw_options.append((opt, text.strip()))
        
        print(f"Found {len(outlaw_options)} Outlaw session options")
        for opt, text in outlaw_options[:5]:
            print(f"  {text[:80]}")
        
        if outlaw_options:
            # Select the first Outlaw session with most events (14 ev)
            # Pick the one with "14 ev" in the text
            target = None
            for opt, text in outlaw_options:
                if "14 ev" in text:
                    target = opt
                    print(f"Selected: {text[:80]}")
                    break
            
            if not target:
                target = outlaw_options[0][0]
                print(f"Fallback to: {outlaw_options[0][1][:80]}")
            
            val = target.get_attribute("value")
            select.select_option(value=val)
            page.wait_for_timeout(3000)
            
            # Capture the replay panel
            el = page.query_selector("#panel-replay")
            if el:
                print("Capturing session-replay-outlaw.png...")
                el.screenshot(path=f"{OUT}/session-replay-outlaw.png")
                print("done")
        else:
            # Try scrolling the dropdown (it may be lazy-loaded)
            print("No Outlaw options found. Trying to scroll dropdown...")
            # Check how many total and if it's paginated
            all_texts = [(opt.text_content() or "").strip()[:60] for opt in options]
            print(f"First 20 options: {all_texts[:20]}")
    
    # Also capture the full dashboard with the Outlaw replay loaded
    print("Capturing dashboard-full-with-replay.png...")
    page.screenshot(path=f"{OUT}/dashboard-full-with-replay.png", full_page=True)
    print("done")

    # Close-up of the stats bar with numbers
    print("Capturing stats-bar.png...")
    el = page.query_selector("#stats-bar")
    if el:
        el.screenshot(path=f"{OUT}/stats-bar.png")
        print("done")

    browser.close()

    print("\n=== Final screenshot inventory ===")
    for f in sorted(os.listdir(OUT)):
        if f.endswith('.png'):
            size = os.path.getsize(f"{OUT}/{f}")
            print(f"  {f}: {size:,} bytes")