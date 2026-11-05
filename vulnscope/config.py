"""Conservative defaults and service associations."""
DEFAULT_PORTS = (21, 22, 25, 80, 443, 3306, 3389, 5432, 8080, 8443, 8765, 8766, 8767, 8768)
MAX_PORTS = 32
MAX_WORKERS = 8
MAX_TIMEOUT = 2.0
MAX_SCAN_SECONDS = 25.0
SERVICE_HINTS = {
    21: "FTP", 22: "SSH", 25: "SMTP", 53: "DNS", 80: "HTTP", 110: "POP3",
    143: "IMAP", 443: "HTTPS", 445: "SMB", 587: "SMTP submission",
    993: "IMAPS", 995: "POP3S", 1433: "MS SQL", 3306: "MySQL",
    3389: "RDP", 5432: "PostgreSQL", 5900: "VNC", 6379: "Redis",
    8000: "HTTP", 8080: "HTTP", 8443: "HTTPS", 8765: "HTTP lab",
    8766: "HTTP lab", 8767: "HTTP lab", 8768: "HTTPS lab",
}
HTTP_PORTS = frozenset((80, 8000, 8080, 8765, 8766, 8767))
HTTPS_PORTS = frozenset((443, 8443, 8768))
BANNER_PORTS = frozenset((21, 22, 25, 110, 143))
