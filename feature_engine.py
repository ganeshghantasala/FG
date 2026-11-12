import ipaddress, re
from urllib.parse import urlparse, urljoin
import tldextract
from bs4 import BeautifulSoup

UCI_FEATURES = [
    "having_IP_Address","URL_Length","Shortining_Service","having_At_Symbol",
    "double_slash_redirecting","Prefix_Suffix","having_Sub_Domain",
    "sslfinal_state","domain_registration_length","favicon","port","https_token",
    "Request_URL","URL_of_Anchor","Links_in_tags","SFH","Submitting_to_email",
    "Abnormal_URL","Redirect","on_mouseover","RightClick","popUpWidnow",
    "Iframe","age_of_domain","DNSRecord","web_traffic","Page_Rank",
    "Google_Index","Links_pointing_to_page","Statistical_report"
]

SHORTENERS = {
    "bit.ly","tinyurl.com","t.co","goo.gl","ow.ly","is.gd","buff.ly",
    "cutt.ly","rebrand.ly","shorturl.at","tiny.cc"
}

SUSPICIOUS_TERMS = {
    "login","signin","verify","verification","secure","account","update",
    "password","bank","wallet","payment","confirm","unlock","suspend",
    "authentication","credential","billing","invoice"
}


# Small, explicit starter list for a review warning. This is not a complete
# brand registry and must not be treated as proof that a URL is malicious.
BRAND_OFFICIAL_DOMAINS = {
    "allegrolokalnie": {"allegrolokalnie.pl"},
    "allegro": {"allegro.pl"},
    "paypal": {"paypal.com"},
    "amazon": {"amazon.com", "amazon.in", "amazon.co.uk", "amazon.de"},
    "google": {"google.com", "google.co.in", "google.in"},
    "microsoft": {"microsoft.com"},
    "apple": {"apple.com"},
    "facebook": {"facebook.com"},
    "instagram": {"instagram.com"},
    "netflix": {"netflix.com"},
    "ebay": {"ebay.com", "ebay.co.uk", "ebay.de"},
    "dhl": {"dhl.com"},
    "ups": {"ups.com"},
    "linkedin": {"linkedin.com"},
    "binance": {"binance.com"},
    "steam": {"steampowered.com", "steamcommunity.com"},
    "bankofamerica": {"bankofamerica.com"},
    "chase": {"chase.com"},
    "wellsfargo": {"wellsfargo.com"},
}


def detect_brand_domain_mismatch(host, registered_domain):
    """Return known brand terms in hostname whose registered domain is not official.

    Matching is restricted to whole hostname labels (after removing hyphens and
    punctuation), not URL paths or arbitrary substrings. Results are review
    candidates only; this intentionally does not change a risk score.
    """
    labels = {
        re.sub(r"[^a-z0-9]", "", label.lower())
        for label in (host or "").lower().rstrip(".").split(".")
        if label
    }
    registered_domain = (registered_domain or "").lower().rstrip(".")
    matches = [brand for brand in BRAND_OFFICIAL_DOMAINS if brand in labels]
    matches = [
        brand for brand in matches
        if not any(brand != other and brand in other for other in matches)
    ]
    return [
        brand for brand in sorted(matches, key=len, reverse=True)
        if registered_domain not in BRAND_OFFICIAL_DOMAINS[brand]
    ]

def safe_url(url):
    url = url.strip()
    if not re.match(r"^https?://", url, re.I):
        url = "https://" + url
    return url

def is_ip(host):
    try:
        ipaddress.ip_address(host)
        return True
    except Exception:
        return False

def private_or_local(host):
    try:
        ip = ipaddress.ip_address(host)
        return ip.is_private or ip.is_loopback or ip.is_link_local or ip.is_reserved
    except Exception:
        low = (host or "").lower().rstrip(".")
        return low in {"localhost", "localhost.localdomain"} or low.endswith(".local")

def tri(flag, good=1, bad=-1):
    return bad if flag else good

def is_external_host(host, registered_domain):
    """Return True when a hostname is outside the registered domain."""
    host = (host or "").strip().lower().rstrip(".")
    registered_domain = (
        (registered_domain or "").strip().lower().rstrip(".")
    )

    if not host or not registered_domain:
        return False

    # Match the exact domain or a genuine subdomain boundary.
    return not (
        host == registered_domain
        or host.endswith("." + registered_domain)
    )


def extract_features(url, html="", original_url=None):
    # Keep the fetched page URL separate from the originally submitted URL.
    page_url = safe_url(url)
    url = safe_url(original_url) if original_url else page_url

    # URL-model features use the original submitted address.
    p = urlparse(url)
    host = p.hostname or ""
    path = p.path or ""
    query = p.query or ""
    ext = tldextract.extract(url)
    submitted_registered = ".".join(
        x for x in [ext.domain, ext.suffix] if x
    )
    brand_mismatch_brands = detect_brand_domain_mismatch(
        host, submitted_registered or host
    )

    # HTML-relative links and page metadata use the actual fetched destination.
    page_p = urlparse(page_url)
    page_host = page_p.hostname or ""
    page_ext = tldextract.extract(page_url)
    registered = ".".join(x for x in [page_ext.domain, page_ext.suffix] if x)

    soup = BeautifulSoup(html or "", "html.parser")
    links = soup.find_all("a", href=True)
    imgs = soup.find_all("img", src=True)
    scripts = soup.find_all("script")
    forms = soup.find_all("form")
    inputs = soup.find_all("input")
    iframes = soup.find_all(["iframe","frame"])

    def abs_url(x):
        try: return urljoin(page_url, x)
        except Exception: return ""

    all_res = []
    for tag, attr in [(x, "src") for x in soup.find_all(src=True)] + [(x, "href") for x in soup.find_all(href=True)]:
        v = tag.get(attr)
        if v: all_res.append(abs_url(v))

    ext_links = 0
    anchor_problem_links = 0
    for a in links:
        href = (a.get("href") or "").strip()
        u = abs_url(href)
        h = (urlparse(u).hostname or "").lower()
        is_external = bool(h and registered and is_external_host(h, registered))
        if is_external:
            ext_links += 1
        # The UCI feature treats placeholder (# / javascript:) and external
        # anchors as potentially problematic. Keep this separate from ext_links
        # because other HTML evidence still uses the external-link count.
        is_placeholder = (not href) or href.lower().startswith(("#", "javascript:"))
        if is_external or is_placeholder:
            anchor_problem_links += 1

    ext_res = 0
    for u in all_res:
        h = (urlparse(u).hostname or "").lower()
        if h and registered and is_external_host(h, registered):
            ext_res += 1

    # Links_in_tags is distinct from Request_URL: only inspect URL-bearing
    # attributes in <meta>, <script>, and <link> tags.
    tag_link_urls = []
    for tag in soup.find_all(["meta", "script", "link"]):
        for attr in ("src", "href"):
            value = (tag.get(attr) or "").strip()
            if value:
                tag_link_urls.append(abs_url(value))

        if tag.name == "meta":
            content = (tag.get("content") or "").strip()
            if content:
                # Include URL-valued metadata and refresh URLs, not descriptions.
                if content.lower().startswith(("http://", "https://", "//")):
                    tag_link_urls.append(abs_url(content))
                else:
                    refresh_match = re.search(r"url\s*=\s*(.+)$", content, re.I)
                    if refresh_match:
                        target = refresh_match.group(1).split(";", 1)[0]
                        target = target.strip().strip(chr(34) + chr(39))
                        if target:
                            tag_link_urls.append(abs_url(target))

    tag_external_links = 0
    for tag_url in tag_link_urls:
        tag_host = (urlparse(tag_url).hostname or "").lower()
        if tag_host and registered and is_external_host(tag_host, registered):
            tag_external_links += 1

    insecure_forms = 0
    external_forms = 0
    abnormal_forms = 0
    mail_forms = 0
    for f in forms:
        action = (f.get("action") or "").strip()
        if action.lower().startswith("mailto:"):
            mail_forms += 1
        if action in {"", "#", "about:blank", "javascript:true"}:
            abnormal_forms += 1
        au = abs_url(action) if action else ""
        ah = (urlparse(au).hostname or "").lower()
        if au and ah and registered and is_external_host(ah, registered):
            external_forms += 1
        if au.startswith("http://"):
            insecure_forms += 1

    visible_text = " ".join(soup.stripped_strings).lower()
    title = (soup.title.get_text(" ", strip=True) if soup.title else "").lower()
    term_hits = sorted({t for t in SUSPICIOUS_TERMS if t in (url.lower() + " " + title + " " + visible_text)})

    # UCI-compatible approximations: -1 suspicious, 0 neutral/unknown, +1 legitimate.
    f = {}
    f["having_IP_Address"] = -1 if is_ip(host) else 1
    f["URL_Length"] = -1 if len(url) >= 75 else (0 if len(url) >= 54 else 1)
    f["Shortining_Service"] = -1 if host.lower() in SHORTENERS else 1
    f["having_At_Symbol"] = -1 if "@" in url else 1
    f["double_slash_redirecting"] = -1 if "//" in path else 1
    f["Prefix_Suffix"] = -1 if "-" in (ext.domain or "") else 1
    dots = host.count(".")
    f["having_Sub_Domain"] = -1 if dots >= 3 else (0 if dots == 2 else 1)
    f["sslfinal_state"] = 1 if p.scheme.lower() == "https" else -1
    f["domain_registration_length"] = 0
    f["favicon"] = 1 if soup.find("link", rel=lambda x: x and "icon" in str(x).lower()) else 0
    f["port"] = -1 if p.port and p.port not in (80,443) else 1
    f["https_token"] = -1 if "https" in (ext.domain or "").lower() else 1
    f["Request_URL"] = -1 if all_res and ext_res / max(len(all_res),1) > 0.22 else 1
    # -1 if >67% of anchors are external or non-functional;
    # 0 if the same combined proportion is between 31% and 67%;
    # 1 if it is below 31%. With no anchors, use 0 (unknown).
    if not links:
        f["URL_of_Anchor"] = 0
    else:
        problematic_anchor_ratio = anchor_problem_links / len(links)
        if problematic_anchor_ratio > 0.67:
            f["URL_of_Anchor"] = -1
        elif 0.31 <= problematic_anchor_ratio <= 0.67:
            f["URL_of_Anchor"] = 0
        else:
            f["URL_of_Anchor"] = 1
    # Dataset-compatible tri-state approximation: <17% external = +1,
    # 17%-81% = neutral (0), >81% external = -1. With no relevant URL
    # references, use 0 (unknown) instead of assuming the page is legitimate.
    if not tag_link_urls:
        f["Links_in_tags"] = 0
    else:
        tag_external_ratio = tag_external_links / len(tag_link_urls)
        if tag_external_ratio < 0.17:
            f["Links_in_tags"] = 1
        elif tag_external_ratio > 0.81:
            f["Links_in_tags"] = -1
        else:
            f["Links_in_tags"] = 0
    # Ternary SFH approximation: blank/non-functional handlers are suspicious,
    # external form handlers are neutral/uncertain, and same-site or absent
    # forms fall into the normal state. If several forms exist, the most
    # concerning observed handler takes precedence.
    if abnormal_forms:
        f["SFH"] = -1
    elif external_forms:
        f["SFH"] = 0
    else:
        f["SFH"] = 1
    f["Submitting_to_email"] = -1 if mail_forms else 1
    f["Abnormal_URL"] = -1 if (not host or "@" in url or "%40" in url.lower()) else 1
    f["Redirect"] = -1 if len(soup.find_all("meta", attrs={"http-equiv": re.compile("refresh", re.I)})) else 1
    f["on_mouseover"] = -1 if any("onmouseover" in str(x).lower() for x in soup.find_all()) else 1
    f["RightClick"] = -1 if re.search(r"(contextmenu|event\.button\s*==\s*2|oncontextmenu)", html or "", re.I) else 1
    f["popUpWidnow"] = -1 if re.search(r"(window\.open\s*\(|alert\s*\()", html or "", re.I) else 1
    f["Iframe"] = -1 if iframes else 1
    f["age_of_domain"] = 0
    f["DNSRecord"] = 0
    f["web_traffic"] = 0
    f["Page_Rank"] = 0
    f["Google_Index"] = 0
    f["Links_pointing_to_page"] = 0
    f["Statistical_report"] = 0

    # Extra live signals used by FakeGuard's evidence-fusion layer.
    identity = 0
    if term_hits: identity += min(1.0, len(term_hits) / 5)
    if forms and any(i.get("type","").lower()=="password" for i in inputs): identity += 0.35
    if external_forms: identity += 0.35
    identity = min(identity, 1.0)

    html_risk = 0
    html_risk += 0.20 if forms else 0
    html_risk += 0.25 if any(i.get("type","").lower()=="password" for i in inputs) else 0
    html_risk += 0.20 if external_forms else 0
    html_risk += 0.10 if insecure_forms else 0
    html_risk += 0.10 if iframes else 0
    html_risk += 0.10 if ext_links and links else 0
    html_risk += 0.05 if mail_forms else 0
    html_risk = min(html_risk, 1.0)

    meta = {
        "registered_domain": registered or page_host,
        "hostname": page_host,
        "submitted_hostname": host,
        "submitted_registered_domain": submitted_registered or host,
        "brand_domain_mismatch": bool(brand_mismatch_brands),
        "brand_mismatch_brands": brand_mismatch_brands,
        "url_length": len(url),
        "external_links": ext_links,
        "total_links": len(links),
        "external_resources": ext_res,
        "forms": len(forms),
        "password_fields": sum(1 for i in inputs if i.get("type","").lower()=="password"),
        "external_form_actions": external_forms,
        "insecure_forms": insecure_forms,
        "iframes": len(iframes),
        "suspicious_terms": term_hits,
        "html_risk": round(html_risk, 3),
        "identity_risk": round(identity, 3),
        "https": page_p.scheme.lower() == "https",
    }
    return f, meta

def feature_vector(f):
    return [f.get(name, 0) for name in UCI_FEATURES]
def feature_vector_for_model(f, feature_names):
    """Build a feature vector in the exact order expected by a model."""
    aliases = {name.lower(): name for name in UCI_FEATURES}
    aliases["popupwindow"] = "popUpWidnow"

    vector = []

    for name in feature_names:
        runtime_name = aliases.get(name.lower())

        if runtime_name is None or runtime_name not in f:
            raise ValueError(
                f"Cannot map model feature: {name}"
            )

        vector.append(f[runtime_name])

    return vector
