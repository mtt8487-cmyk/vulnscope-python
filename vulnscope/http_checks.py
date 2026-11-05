"""Read-only HTTP headers via direct connections; no redirects, proxies or crawling."""
import http.client
import ssl


def get_headers(host: str, port: int, https: bool, timeout: float) -> dict:
    conn = None
    result = {"port": port, "scheme": "https" if https else "http", "status": None,
              "headers": {}, "error": None, "redirect": None}
    try:
        if https:
            conn = http.client.HTTPSConnection(host, port=port, timeout=timeout, context=ssl.create_default_context())
        else:
            conn = http.client.HTTPConnection(host, port=port, timeout=timeout)
        conn.request("HEAD", "/", headers={"User-Agent": "VulnScope/1.0 (authorized-read-only)", "Connection": "close"})
        response = conn.getresponse()
        result["status"] = response.status
        result["headers"] = {k.lower(): v[:512] for k, v in response.getheaders()}
        if response.status in (301, 302, 303, 307, 308):
            result["redirect"] = result["headers"].get("location", "(location not supplied)")
    except (OSError, ssl.SSLError, http.client.HTTPException, ValueError) as exc:
        result["error"] = f"{type(exc).__name__}: {str(exc)[:180]}"
    finally:
        if conn:
            conn.close()
    return result
