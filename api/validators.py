import ipaddress
import socket
import urllib.parse
import json
import yaml
import requests
from typing import Tuple, Optional, Dict, Any

BLOCKED_IP_NETWORKS = [
    ipaddress.ip_network('127.0.0.0/8'),        # Loopback
    ipaddress.ip_network('10.0.0.0/8'),         # Private class A
    ipaddress.ip_network('172.16.0.0/12'),      # Private class B
    ipaddress.ip_network('192.168.0.0/16'),     # Private class C
    ipaddress.ip_network('169.254.0.0/16'),     # Link-local / Cloud Metadata (AWS, GCP, Azure)
    ipaddress.ip_network('0.0.0.0/8'),          # Unspecified
    ipaddress.ip_network('100.64.0.0/10'),      # Carrier grade NAT
    ipaddress.ip_network('192.0.0.0/24'),       # IETF Protocol Assignments
    ipaddress.ip_network('192.0.2.0/24'),       # TEST-NET-1
    ipaddress.ip_network('198.18.0.0/15'),      # Network benchmark tests
    ipaddress.ip_network('198.51.100.0/24'),    # TEST-NET-2
    ipaddress.ip_network('203.0.113.0/24'),     # TEST-NET-3
    ipaddress.ip_network('224.0.0.0/4'),        # Multicast
    ipaddress.ip_network('240.0.0.0/4'),        # Reserved
    ipaddress.ip_network('255.255.255.255/32'), # Broadcast
    ipaddress.ip_network('::1/128'),            # IPv6 Loopback
    ipaddress.ip_network('fc00::/7'),           # IPv6 Unique Local
    ipaddress.ip_network('fe80::/10'),          # IPv6 Link-Local
]

def is_ip_blocked(ip_str: str) -> bool:
    """Check if an IP address falls within private/internal/cloud-metadata blocked ranges."""
    try:
        ip_obj = ipaddress.ip_address(ip_str)
        if ip_obj.is_private or ip_obj.is_loopback or ip_obj.is_link_local or ip_obj.is_multicast or ip_obj.is_reserved or ip_obj.is_unspecified:
            return True
        for net in BLOCKED_IP_NETWORKS:
            if ip_obj in net:
                return True
        return False
    except ValueError:
        return True

def validate_remote_url_ssrf(url: str) -> Tuple[bool, Optional[str]]:
    """Strict SSRF validation on a user-provided remote URL."""
    if not url or not isinstance(url, str):
        return False, "URL cannot be empty."
    
    url = url.strip()
    parsed = urllib.parse.urlparse(url)
    
    # 1. Enforce scheme
    if parsed.scheme.lower() not in ('http', 'https'):
        return False, f"Unsupported scheme '{parsed.scheme}'. Only HTTP and HTTPS are permitted."
    
    # 2. Enforce hostname presence
    hostname = parsed.hostname
    if not hostname:
        return False, "Invalid URL: Hostname is missing."
    
    # 3. Block localhost string variations
    if hostname.lower() in ('localhost', '127.0.0.1', '::1', '0.0.0.0', 'local', 'intranet', 'internal'):
        return False, f"Target host '{hostname}' points to a local or internal address (SSRF Protection)."
    
    # 4. Resolve DNS and check all resolved IPs
    try:
        addr_info = socket.getaddrinfo(hostname, parsed.port or (443 if parsed.scheme == 'https' else 80), socket.AF_UNSPEC, socket.SOCK_STREAM)
        resolved_ips = set()
        for item in addr_info:
            ip = item[4][0]
            resolved_ips.add(ip)
            if is_ip_blocked(ip):
                return False, f"Target host '{hostname}' resolves to private/internal IP {ip} (SSRF Protection)."
    except socket.gaierror:
        return False, f"Could not resolve hostname '{hostname}'."
    except Exception as e:
        return False, f"DNS validation failed: {str(e)}"
        
    return True, None

def fetch_remote_spec_safely(url: str, timeout: int = 10, max_size_bytes: int = 5 * 1024 * 1024) -> Tuple[Optional[str], Optional[str]]:
    """Safely fetch a remote OpenAPI specification with SSRF protection, size limits, and timeout."""
    is_safe, error = validate_remote_url_ssrf(url)
    if not is_safe:
        return None, error
        
    try:
        session = requests.Session()
        session.max_redirects = 3
        
        headers = {
            'User-Agent': 'SentinelAPI-SecurityScanner/2.4 (OpenAPI Importer; SSRF-Protected)',
            'Accept': 'application/json, application/yaml, application/x-yaml, text/yaml, text/plain, */*'
        }
        
        # Stream response to strictly enforce max response size
        response = session.get(url, headers=headers, timeout=timeout, stream=True, allow_redirects=False)
        
        # Validate redirects manually to prevent SSRF via redirect chaining
        redirect_count = 0
        while response.is_redirect and redirect_count < 3:
            redirect_url = response.headers.get('Location')
            if not redirect_url:
                break
            redirect_url = urllib.parse.urljoin(url, redirect_url)
            is_redirect_safe, redirect_err = validate_remote_url_ssrf(redirect_url)
            if not is_redirect_safe:
                return None, f"Redirect blocked: {redirect_err}"
            url = redirect_url
            response = session.get(url, headers=headers, timeout=timeout, stream=True, allow_redirects=False)
            redirect_count += 1
            
        if response.status_code != 200:
            return None, f"Remote server returned HTTP {response.status_code}."
            
        content_bytes = bytearray()
        for chunk in response.iter_content(chunk_size=8192):
            content_bytes.extend(chunk)
            if len(content_bytes) > max_size_bytes:
                return None, f"Remote specification exceeds maximum permitted size ({max_size_bytes // 1024 // 1024} MB)."
                
        decoded_content = content_bytes.decode('utf-8', errors='replace')
        return decoded_content, None
        
    except requests.exceptions.Timeout:
        return None, "Connection timed out while fetching remote specification."
    except requests.exceptions.RequestException as e:
        return None, f"Network error fetching specification: {str(e)}"
    except Exception as e:
        return None, f"Failed to fetch specification: {str(e)}"

def safe_parse_spec_content(raw_text: str) -> Tuple[Optional[Dict[str, Any]], Optional[str], Optional[str]]:
    """Parse JSON or YAML text safely into a Python dictionary. Returns (spec_dict, format_type, error)."""
    if not raw_text or not raw_text.strip():
        return None, None, "Specification content is empty."
        
    if len(raw_text) > 10 * 1024 * 1024:
        return None, None, "Specification content exceeds 10 MB limit."
        
    # Try JSON first
    raw_stripped = raw_text.strip()
    if raw_stripped.startswith('{') or raw_stripped.startswith('['):
        try:
            parsed = json.loads(raw_text)
            if isinstance(parsed, dict):
                return parsed, 'json', None
            return None, None, "Invalid JSON structure: top-level object must be a dictionary."
        except json.JSONDecodeError as e:
            # Fall through to YAML attempt if JSON decode fails
            pass
            
    # Try YAML (using safe_load)
    try:
        parsed = yaml.safe_load(raw_text)
        if isinstance(parsed, dict):
            return parsed, 'yaml', None
        return None, None, "Invalid YAML structure: top-level object must be a dictionary."
    except yaml.YAMLError as e:
        return None, None, f"Failed to parse as JSON or YAML: {str(e)}"
    except Exception as e:
        return None, None, f"Parsing error: {str(e)}"
