import os, json, urllib.request

# Check API key
key = os.environ.get("ANTHROPIC_API_KEY", "")
print(f"API key set: {bool(key)} ({len(key)} chars)")

# Test the local endpoint
try:
    req_data = json.dumps({"message": "How do I request time off?"}).encode()
    req = urllib.request.Request(
        "https://ap-jamievavroaiprowler-f68efeed.ai-prowler.com/hr-api/ai-chat",
        data=req_data,
        headers={"Content-Type": "application/json"}
    )
    with urllib.request.urlopen(req, timeout=10) as resp:
        data = json.loads(resp.read())
        print(f"Response: {data}")
except Exception as e:
    print(f"Error: {e}")
