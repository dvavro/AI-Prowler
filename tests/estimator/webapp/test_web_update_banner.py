""""A newer version is installed" (2026-11-13, David): a deploy that changed only the Estimator's web files never
raised the Jobs app's update banner (its version covered only jobs/sw.js, index.html and manifest.json), and the
Estimator's own pages had no update check at all."""
import shutil
import time
from pathlib import Path

from estimator.api import router

API = "/estimator-api"
ROOT = Path(router.WEB_DIR).parents[2]


def _copy_web(tmp_path):
    web = tmp_path / "estimator" / "ui" / "web"
    web.mkdir(parents=True)
    for n in ("index.html", "app.js", "app.css"):
        shutil.copy(router.WEB_DIR / n, web / n)
    (web / "app.js.bak7").write_text("old backup", encoding="utf-8")
    return web


def test_health_reports_the_web_build_and_it_follows_the_files(call, tmp_path, monkeypatch):
    b = call("GET", f"{API}/health").json()["build"]
    assert b and len(b) == 10
    web = _copy_web(tmp_path)
    monkeypatch.setattr(router, "WEB_DIR", web)
    first = router.web_build()
    (web / "app.js.bak7").write_text("a backup changed", encoding="utf-8")       # backups don't count
    assert router.web_build() == first
    time.sleep(0.01)
    (web / "app.js").write_text((web / "app.js").read_text(encoding="utf-8") + "\n// changed\n", encoding="utf-8")
    assert router.web_build() != first


def test_jobs_app_version_includes_the_embedded_estimator(tmp_path):
    import ai_prowler_mcp as ap
    jobs = tmp_path / "jobs"
    jobs.mkdir()
    for n in ("index.html", "manifest.json", "sw.js"):
        shutil.copy(ROOT / "jobs" / n, jobs / n)
    web = _copy_web(tmp_path)
    sw = (jobs / "sw.js").read_bytes()
    v1, badge1 = ap._compute_pwa_sw_cache_version(str(jobs), sw), ap._compute_pwa_build(str(jobs), b"page")
    (web / "app.js").write_text("// a new Estimator\n", encoding="utf-8")
    v2, badge2 = ap._compute_pwa_sw_cache_version(str(jobs), sw), ap._compute_pwa_build(str(jobs), b"page")
    assert v1 != v2 and badge1 != badge2                  # the Jobs app's banner and badge now change with it
    # Other apps (Remote, HR...) don't carry the Estimator.
    other = tmp_path / "remote"
    other.mkdir()
    assert ap._embedded_estimator_bytes(str(other)) == b""


def test_page_loads_its_scripts_at_versioned_addresses(call):
    """Cloudflare tells browsers to keep .js/.css for 4 hours whatever we send, so a computer kept the old screens
    after an update; every script and style sheet in the page now carries ?v=<build>, a new address per version."""
    import re
    build = call("GET", f"{API}/health").json()["build"]
    for path in ("/estimator/", "/estimator/index.html", "/estimator/?embed=1"):
        page = call("GET", path).body.decode("utf-8")
        refs = re.findall(r'(?:src|href)="([^"]+\.(?:js|css)[^"]*)"', page)
        assert refs and all(r.endswith("?v=" + build) for r in refs), refs
        assert 'src="tour.js?v=' in page and 'href="app.css?v=' in page
    r = call("GET", f"/estimator/app.js?v={build}")
    assert r.status == 200 and b"makeZoomable" in r.body


def test_estimator_page_watches_for_a_new_version():
    js = (router.WEB_DIR / "app.js").read_text(encoding="utf-8")
    for part in ("function watchForUpdates()", "watchForUpdates();", 'API + "/health"', 'id: "update-banner"',
                 'id: "update-refresh"', 'id: "update-later"', "if (EMBEDDED) return;", "location.reload()"):
        assert part in js, part
    assert ".update-banner" in (router.WEB_DIR / "app.css").read_text(encoding="utf-8")
