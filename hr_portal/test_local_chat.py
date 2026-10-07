import urllib.request, json

# Test the hr-api/ai-chat endpoint locally
try:
    req_data = json.dumps({"message": "payroll"}).encode()
    req = urllib.request.Request(
        "http://localhost:30701/hr-api/ai-chat",
        data=req_data,
        headers={"Content-Type": "application/json"}
    )
    with urllib.request.urlopen(req, timeout=5) as resp:
        data = json.loads(resp.read())
        print(f"✅ Response: {data.get('reply','')[:200]}")
except Exception as e:
    print(f"❌ Error: {e}")
