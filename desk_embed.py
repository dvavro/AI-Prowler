"""
desk_embed.py — Share & embed for the customer page (booking-spec.md §4, Phase 6).

What the owner copies to put booking on their own website:
    link     https://<link>/book            (optionally ?service=<code>)
    button   a styled "Book online" link that opens the page
    embed    an <iframe> plus a few lines of script that size it to the page

The embed only works on the websites listed in Allowed websites (booking_allowed_sites,
local-only): the page is served with Content-Security-Policy: frame-ancestors for exactly
those sites (desk_portal.frame_policy). The link and the button work anywhere.
"""
from __future__ import annotations

import html
import urllib.parse

DEFAULT_ACCENT = "#0b7fab"


def page_url(base_url: str, service_code: str = "") -> str:
    base = (base_url or "").rstrip("/")
    url = f"{base}/book" if base else "/book"
    return url + (f"?service={urllib.parse.quote(service_code)}" if service_code else "")


def snippets(base_url: str, *, service_code: str = "", label: str = "Book online", accent: str = "") -> dict:
    url = page_url(base_url, service_code)
    acc = accent or DEFAULT_ACCENT
    esc_url, esc_label = html.escape(url, quote=True), html.escape(label or "Book online")
    button = (f'<a href="{esc_url}" target="_blank" rel="noopener" style="display:inline-block;padding:12px 22px;'
              f'border-radius:8px;background:{acc};color:#fff;font:600 16px/1.2 system-ui,sans-serif;'
              f'text-decoration:none">{esc_label}</a>')
    frame_url = url + ("&" if "?" in url else "?") + "embed=1"
    embed = (f'<iframe id="aiprowler-book" src="{html.escape(frame_url, quote=True)}" title="{esc_label}" '
             'style="width:100%;min-height:640px;border:0" loading="lazy"></iframe>\n'
             '<script>window.addEventListener("message",function(e){var f=document.getElementById("aiprowler-book");'
             'if(f&&e.source===f.contentWindow&&e.data&&e.data.aiprowlerHeight){'
             'f.style.height=Math.max(400,+e.data.aiprowlerHeight+20)+"px";}});</script>')
    return {"link": url, "button": button, "embed": embed}


def embed_note(sites: list) -> str:
    if not sites:
        return ("No websites are allowed yet, so the embedded page won't show inside another site — the link and "
                "button still work. Add your website below to use the embed.")
    return "The embedded page shows only on: " + ", ".join(sites) + "."
