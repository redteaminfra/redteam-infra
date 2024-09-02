#!/bin/bash

# Define your domains
DOMAINS=("your_domain1.com" "your_domain2.com")

# Define the webroot path for the ACME challenge
WEBROOT_PATH="/var/www/certbot"

# Ensure the webroot path exists
mkdir -p $WEBROOT_PATH

# Loop through each domain and renew the certificate
for DOMAIN in "${DOMAINS[@]}"; do
    sudo certbot certonly --manual --preferred-challenges=http --manual-auth-hook "echo 'auth hook'" --manual-cleanup-hook "echo 'cleanup hook'" --webroot -w $WEBROOT_PATH -d $DOMAIN --force-renew
done

# Reload Nginx to apply the new certificates
sudo systemctl reload nginx