# Copyright (c) 2026, Oracle and/or its affiliates.
"""Safe, container-native request observability for managed web sites.

The shared OpenResty front has the original peer address either in the
PROXY-protocol metadata (TLS) or in the trusted header it sets while handling
HTTP.  A per-site container is the HTTP/TLS termination boundary, so its
stdout access log is the authoritative request audit point.
"""

from __future__ import annotations


def render_managed_site_observability_config(*, receives_proxy_protocol: bool = True) -> str:
    """Render an http-context include for one managed site container.

    Deliberately omit URI, request headers, request bodies, and upload paths:
    those can contain operator gate values or uploaded-file metadata.  The
    original-client value is used only for observability and forwarded backend
    metadata; it is never used for authorization.
    """
    fallback = "$proxy_protocol_addr" if receives_proxy_protocol else "$remote_addr"
    transport_note = (
        "# The TLS stream front regenerates a PROXY header. Its current source is\n"
        "# the selected middle node until WI-0336 lands."
        if receives_proxy_protocol
        else "# The HTTP front supplies X-Real-IP from edge PROXY metadata.\n"
        "# Direct local maintenance traffic falls back to peer address."
    )
    return f"""# Managed by Barragan: log the address supplied by the shared front.
{transport_note}
map $http_x_real_ip $barragan_original_client_ip {{
    default $http_x_real_ip;
    \"\" {fallback};
}}

# Keep container logs useful without recording request targets, credentials,
# query strings, or uploaded-file metadata.
log_format barragan_site '$barragan_original_client_ip [$time_local] '
                         'method=$request_method protocol=$server_protocol '
                         'status=$status bytes=$body_bytes_sent host=$host '
                         'request_time=$request_time upstream_status=$upstream_status '
                         'upstream_time=$upstream_response_time';
access_log /dev/stdout barragan_site;
error_log /dev/stderr warn;
"""
