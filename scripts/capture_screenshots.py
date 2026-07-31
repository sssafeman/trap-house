#!/usr/bin/env python3
"""Capture dashboard screenshots for the trap-house portfolio."""
import os
from playwright.sync_api import sync_playwright

OUT = os.path.expanduser("~/projects/trap-house/docs/img")
os.makedirs(OUT, exist_ok=True)

with sync_playwright() as p:
    browser = p.chromium.launch(headless=True)
    context = browser.new_context(viewport={"width": 1920, "height": 1080})
    page = context.new_page()

    # === Frontend (port 8001) ===
    print("Loading frontend at localhost:8001...")
    page.goto("http://localhost:8001", wait_until="networkidle", timeout=30000)
    page.wait_for_timeout(3000)

    # Screenshot 1: Dashboard overview (top of page)
    print("Capturing dashboard-overview.png...")
    page.screenshot(path=f"{OUT}/dashboard-overview.png")
    print("done")

    # List all clickable elements to find tabs
    elements = page.query_selector_all("button, .tab, [role='tab'], a[href], nav a, .nav-link")
    tab_texts = []
    for el in elements[:40]:
        text = el.text_content()
        if text and text.strip():
            tab_texts.append(text.strip()[:60])
    print(f"Clickable elements found: {tab_texts[:25]}")

    # Screenshot 2: Full page scroll
    print("Capturing dashboard-fullpage.png...")
    page.add_style_tag(content=".topnav { position: static !important; }")
    page.screenshot(path=f"{OUT}/dashboard-fullpage.png", full_page=True)
    print("done")

    # Try clicking on map-related elements
    clicked_map = False
    for el in elements[:40]:
        text = el.text_content()
        if text and ("map" in text.lower() or "attack" in text.lower()):
            print(f"Clicking: {text.strip()[:60]}")
            el.click()
            page.wait_for_timeout(2000)
            print(f"Capturing attack-map.png...")
            page.screenshot(path=f"{OUT}/attack-map.png")
            print("done")
            clicked_map = True
            break

    if not clicked_map:
        print("No map tab found. Trying scrolling for map section...")
        # Scroll down and capture sections
        for scroll_pos in [500, 1000, 1500, 2000]:
            page.evaluate(f"window.scrollTo(0, {scroll_pos})")
            page.wait_for_timeout(1000)
            print(f"Capturing dashboard-scroll-{scroll_pos}.png...")
            page.screenshot(path=f"{OUT}/dashboard-scroll-{scroll_pos}.png")
            print("done")

    # === Grafana (port 3000) ===
    print("\nLoading Grafana at localhost:3000...")
    page.goto("http://localhost:3000", wait_until="networkidle", timeout=30000)
    page.wait_for_timeout(3000)

    # Grafana may need login
    print(f"Grafana URL: {page.url}")
    print("Capturing grafana-overview.png...")
    page.screenshot(path=f"{OUT}/grafana-overview.png")
    print("done")

    # Check if login page
    content = page.content()
    if "login" in content.lower() or "password" in content.lower():
        print("Grafana login page detected. Capturing as grafana-login.png...")
        page.screenshot(path=f"{OUT}/grafana-login.png")
        print("done")

    browser.close()
    print("\n=== All screenshots captured ===")
    # List files
    for f in sorted(os.listdir(OUT)):
        if f.endswith('.png'):
            size = os.path.getsize(f"{OUT}/{f}")
            print(f"  {f}: {size:,} bytes")