import urllib.request, json

# Test 1: Does the portal load?
try:
    r = urllib.request.urlopen("https://ap-jamievavroaiprowler-f68efeed.ai-prowler.com/hr_portal/", timeout=8)
    html = r.read().decode('utf-8', errors='replace')
    print(f"Portal loads: YES ({len(html):,} bytes)")
    print(f"Has openITModal: {'openITModal' in html}")
    print(f"Has openFeedbackModal: {'openFeedbackModal' in html}")
    print(f"Has it-modal div: {'id=\"it-modal\"' in html}")
    print(f"Has fb-type input: {'id=\"fb-type\"' in html}")
except Exception as e:
    print(f"Portal load FAILED: {e}")
