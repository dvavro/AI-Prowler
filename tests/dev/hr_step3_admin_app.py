"""HR server-only conversion, step 3 (2026-10-11, David) — the HR Admin app.

  * moves off the retired /hr/ mount onto its own /hr_admin/ (service worker,
    install manifest, offline cache, notification deep link)
  * the service worker no longer caches /hr-api responses (employee data was
    being stored in the device's browser cache)
  * sign-in: Name + AI-Prowler token -> POST /hr-api/auth/login (owners and
    managers; replaces "paste a bearer token"); Sign Out also ends the
    session on the server (/pwa-logout)
Checks every anchor before writing. ASCII output."""
from pathlib import Path

REPO = Path(__file__).resolve().parents[2]
D = REPO / "hr_admin"


def edit(path, pairs):
    raw = path.read_bytes().decode("utf-8")
    nl = "\r\n" if "\r\n" in raw else "\n"
    s = raw.replace("\r\n", "\n")
    for old, new in pairs:
        assert s.count(old) == 1, f"{path.name}: expected 1x {old[:60]!r}, found {s.count(old)}"
        s = s.replace(old, new)
    path.write_bytes(s.replace("\n", nl).encode("utf-8"))
    print(f"{path.relative_to(REPO)}: {len(pairs)} change(s)")


edit(D / "manifest.json", [
    ('"start_url": "/hr/",', '"start_url": "/hr_admin/",'),
    ('"scope": "/hr/",', '"scope": "/hr_admin/",'),
])

edit(D / "sw.js", [
    ("// offline fallback shape, different mount point (/hr/) and cache prefix (hr-).",
     "// offline fallback shape, different mount point (/hr_admin/) and cache prefix (hr-).\n"
     "// 2026-10-11: moved from the retired /hr/ mount; /hr-api responses (employee\n"
     "// data) are never written to the device cache."),
    ("const OFFLINE_ASSETS = ['/hr/', '/hr/index.html', '/hr/manifest.json'];",
     "const OFFLINE_ASSETS = ['/hr_admin/', '/hr_admin/index.html', '/hr_admin/manifest.json'];"),
    ("""      var resClone = res.clone();
      caches.open(CACHE_NAME).then(function(c) { c.put(e.request, resClone); }).catch(function(){});
      return res;""",
     """      if (e.request.url.indexOf('/hr-api') === -1) {   // never cache employee data
        var resClone = res.clone();
        caches.open(CACHE_NAME).then(function(c) { c.put(e.request, resClone); }).catch(function(){});
      }
      return res;"""),
    ("var url = taskId ? '/hr/?task=' + taskId : '/hr/';",
     "var url = taskId ? '/hr_admin/?task=' + taskId : '/hr_admin/';"),
    ("if (clients[i].url.startsWith(self.location.origin + '/hr/') && 'focus' in clients[i]) {",
     "if (clients[i].url.startsWith(self.location.origin + '/hr_admin/') && 'focus' in clients[i]) {"),
])

edit(D / "index.html", [
    ("navigator.serviceWorker.register('/hr/sw.js')",
     "navigator.serviceWorker.register('/hr_admin/sw.js')"),
    ("""      <div id="auth-admin-form">
        <div class="auth-input-group">
          <label>Bearer Token</label>
          <input class="auth-input" type="password" id="auth-token" placeholder="Paste your bearer token" autocomplete="off">
        </div>
        <button class="auth-btn" onclick="loginAdmin()">Sign In as HR Admin</button>
      </div>""",
     """      <div id="auth-admin-form">
        <!-- 2026-10-11 (David): sign in with your AI-Prowler account (owners
             and managers) — same name + token as the Jobs app. -->
        <div class="auth-input-group">
          <label>Your name</label>
          <input class="auth-input" type="text" id="auth-name" placeholder="As set up on this AI-Prowler server" autocomplete="username">
        </div>
        <div class="auth-input-group">
          <label>AI-Prowler token</label>
          <input class="auth-input" type="password" id="auth-token" placeholder="Your AI-Prowler password / token" autocomplete="current-password"
                 onkeydown="if(event.key==='Enter')loginAdmin()">
        </div>
        <button class="auth-btn" onclick="loginAdmin()">Sign In as HR Admin</button>
      </div>"""),
    ("""async function loginAdmin() {
  const token = document.getElementById('auth-token').value.trim();
  if (!token) { showAuthError('Please enter your bearer token.'); return; }
  try {
    const res = await apiFetch('/config', { token });
    if (res.ok || res.status === 200) {
      state.token = token;
      state.role = 'admin';
      localStorage.setItem(STORAGE_TOKEN_KEY, token);
      document.getElementById('auth-screen').classList.add('hidden');
      initAdminApp();
    } else if (res.status === 401) {
      localStorage.removeItem(STORAGE_TOKEN_KEY);
      showAuthError('Invalid token. Please try again.');
    } else {
      showAuthError('Login failed. Check server connection.');
    }
  } catch(e) {
    showAuthError('Cannot reach server. Check your connection.');
  }
}""",
     """async function loginAdmin() {
  // 2026-10-11 (David): AI-Prowler account sign-in (server only) — owners and
  // managers. The server checks name + token and hands back a session token
  // (same idle timeout and sign-out as the Jobs app).
  const name  = (document.getElementById('auth-name') || {value: ''}).value.trim();
  const token = document.getElementById('auth-token').value.trim();
  if (!name || !token) { showAuthError('Please enter your name and AI-Prowler token.'); return; }
  try {
    const res = await fetch(`${API_BASE}/auth/login`, {
      method: 'POST', headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ name, token })
    });
    let data = {};
    try { data = await res.json(); } catch(e) {}
    if (res.ok && data.access_token) {
      state.token = data.access_token;
      state.role = 'admin';
      localStorage.setItem(STORAGE_TOKEN_KEY, data.access_token);
      document.getElementById('auth-token').value = '';
      document.getElementById('auth-screen').classList.add('hidden');
      initAdminApp();
    } else {
      localStorage.removeItem(STORAGE_TOKEN_KEY);
      showAuthError(data.message || (res.status === 401
        ? 'Name or password not recognized.'
        : 'Sign-in failed. Check the server connection.'));
    }
  } catch(e) {
    showAuthError('Cannot reach server. Check your connection.');
  }
}"""),
    ("""function logout() {
  localStorage.removeItem(STORAGE_TOKEN_KEY);""",
     """function logout() {
  // End the session on the server too (2026-10-11) — not just in this browser.
  try {
    if (state.token) fetch('/pwa-logout', { method: 'POST',
      headers: { 'Authorization': `Bearer ${state.token}` } }).catch(function(){});
  } catch(e) {}
  localStorage.removeItem(STORAGE_TOKEN_KEY);"""),
])
