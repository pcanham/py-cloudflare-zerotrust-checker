#!/bin/bash

if [[ "$(uname)" == "Darwin" ]]; then
  echo "Running on macOS. Continuing..."
else
  echo "Unsupported OS. Exiting with code 3."
  exit 3
fi

# Create directories
mkdir -p ~/.ca-certificates
mkdir -p ~/.colima/default

# Export certificates from Keychain
security find-certificate -a -p /System/Library/Keychains/SystemRootCertificates.keychain > ~/.ca-certificates/root_certs.pem
security find-certificate -a -p /Library/Keychains/System.keychain >> ~/.ca-certificates/root_certs.pem

# Create or update Colima configuration
cat << EOF > ~/.colima/default/colima.yaml
provision:
  - mode: system
    script: |
      CERTS="/Users/$(whoami)/.ca-certificates"
      cp \${CERTS}/* /usr/local/share/ca-certificates/
      update-ca-certificates
      systemctl daemon-reload
      systemctl restart docker
EOF

# Stop Colima if it's running
colima stop

# Start Colima with the new configuration
colima start

echo "Certificates exported and Colima configured and restarted"
