import urllib.request

try:
    r = urllib.request.urlopen("https://ap-jamievavroaiprowler-f68efeed.ai-prowler.com/hr_portal/", timeout=8)
    html = r.read().decode('utf-8', errors='replace')
    print(f"Portal size: {len(html):,} bytes")
    print(f"openITModal: {'openITModal' in html}")
    print(f"openFeedbackModal: {'openFeedbackModal' in html}")
    it_div = 'id="it-modal"' in html
    fb_type = 'id="fb-type"' in html
    print(f"it-modal div: {it_div}")
    print(f"fb-type input: {fb_type}")
    # Find the IT Support line
    idx = html.find('openITModal')
    if idx > 0:
        print(f"openITModal context: ...{html[idx-50:idx+80]}...")
except Exception as e:
    print(f"FAILED: {e}")
