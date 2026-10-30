# go_simple_upload_server

Deploy [mayth/go-simple-upload-server](https://github.com/mayth/go-simple-upload-server)
on Homebase as `go-simple-upload-server.service`. Publish it through the
engagement's normal `edge -> middle -> proxy -> homebase:9999` HTTP/HTTPS
path. The Homebase listener is a backend service, not a public listener.

## Publish an upload route

Use an engagement-specific site on the selected proxy. Keep the public route
credential separate from the private backend credential: the proxy checks the
public value, then replaces it before forwarding the request to Homebase.

```nginx
map $http_authorization $upload_route_allowed {
    default 0;
    "Bearer PUBLIC_ROUTE_TOKEN" 1;
}

server {
    listen 8081 proxy_protocol ssl;
    server_name uploads.example.com;

    # TLS and PROXY-protocol settings belong to this site container.
    client_max_body_size 500000000;

    location /upload {
        if ($upload_route_allowed = 0) { return 404; }

        proxy_pass http://homebase:9999;
        proxy_set_header Authorization "Bearer BACKEND_TOKEN";
        proxy_set_header Host $host;
        proxy_set_header X-Real-IP $remote_addr;
        proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
        proxy_set_header X-Forwarded-Proto $scheme;
        proxy_request_buffering off;
        proxy_read_timeout 600s;
        proxy_send_timeout 600s;
    }
}
```

Replace both placeholders through your secret-distribution process; do not put
real tokens in source control. The site's route limit must be no larger than
the server's `go_simple_upload_server_max_upload_size_bytes`. The effective
upload limit is the lower of those two limits. The role defaults to
500,000,000 bytes (500 MB).

## Role behavior

- Pins Mayth release `v2.1.1` and builds it with a checksum-pinned,
  role-private Go toolchain. This supports Ubuntu 20.04 without replacing its
  system Go installation.
- Runs as the `go-simple-upload-server` system account and stores files in
  `/opt/go-simple-upload-server/files` by default. The document root is
  service-owned `0775`, and the systemd service uses `UMask=0002`, so new
  uploads are `0664`: the service owner/group can write and ordinary local
  engagement users can read without access to the service configuration.
- Enables read-write bearer-token authentication by default. When no token is
  supplied, the first run generates and later runs retain one in
  `/etc/go-simple-upload-server/config.json`.
- Sets no read timeout by default so a legitimate large upload is not rejected
  by the application's short default timeout.
- Keeps `/etc/go-simple-upload-server` at `root:go-simple-upload-server`
  mode `0750`, allowing the service account to traverse its configuration
  directory without exposing its retained token.
- Verifies the configured listener after role convergence.

## Role variables

```yaml
go_simple_upload_server_version: "v2.1.1"
go_simple_upload_server_bind_address: "0.0.0.0:9999"
go_simple_upload_server_root_directory: "/opt/go-simple-upload-server/files"
go_simple_upload_server_token: ""
go_simple_upload_server_enable_auth: true
go_simple_upload_server_max_upload_size_bytes: 500000000
go_simple_upload_server_read_timeout_seconds: -1
go_simple_upload_server_write_timeout_seconds: 0
```

When `go_simple_upload_server_token` is empty, the role reuses the token
retained in `/etc/go-simple-upload-server/config.json` or generates a new
20-character backend token on first installation. The configuration is mode
`0640`, owned by `root:go-simple-upload-server`; its parent directory is mode
`0750` with the same group. Token-bearing Ansible tasks suppress their output.
```yaml
- hosts: homebase
  become: true
  roles:
    - role: go_simple_upload_server
```

## Diagnostic check: private listener only

Use this only from an authorized private/core host when diagnosing the backend.
Normal operators and public clients use the configured route above.

```bash
# Missing backend token: expected 401.
curl -i http://homebase:9999/files/example.bin

# Authorized multipart upload: expected 201.
curl -i \
  -H 'Authorization: Bearer BACKEND_TOKEN' \
  -F 'file=@example.bin' \
  http://homebase:9999/upload
```

## Migrating from `go-fileserver`

This role replaces the former `go-fileserver` role. Update playbooks to use
`go_simple_upload_server` and configure the variables documented above; the
old role variables and service configuration are not compatibility aliases.
The new systemd service is `go-simple-upload-server.service`. Back up existing
uploads and configuration, then stop and disable `go-fileserver.service` before
starting the replacement if both use the same port. Select the intended upload
root explicitly and update proxy routes and authentication to match the new
backend. Existing service configuration and stored files are not migrated
automatically.
