#!/usr/bin/env bash

# The provided script is an installation script for the akc-dcm-cli tool. It first checks if the VERSION argument is provided. If it is not, it fetches the latest version from the GitHub releases API.
# Next, it gets the current OS type and machine architecture. It then uses the GOARCH and GOOS variables to determine the correct download URL for the akc-dcm-cli tool.
# The script then downloads the tarball, extracts it, and moves the akc-dcm-cli binary to the /usr/local/bin directory. It then sets the permissions for the binary and removes the tarball.
# Finally, the script prints the version of the akc-dcm-cli tool

VERSION=$1
if [ -z "$VERSION" ]; then
  VERSION=$(curl -s "https://api.github.com/repos/adityajoshi12/akc-dcm-cli/releases/latest" | jq -r '.tag_name')
fi

# Get the current OS type.
OS=$(uname -s)

# Get the current machine architecture.
ARCH=$(uname -m)

# Determine the GOARCH value based on the machine architecture.
case $ARCH in
  x86_64)
    GOARCH=amd64
    ;;
  aarch64)
    GOARCH=arm64
    ;;
  arm64)
    GOARCH=arm64
    ;;
  *)
    echo "Unsupported architecture: $ARCH"
    exit 1
    ;;
esac

# Determine the GOOS value based on the OS type.
case $OS in
  Darwin)
    GOOS=darwin
    ;;
  Linux)
    GOOS=linux
    ;;
  *)
    echo "Unsupported OS: $OS"
    exit 1
    ;;
esac


curl -L "https://github.com/adityajoshi12/akc-dcm-cli/releases/download/${VERSION}/akc-dcm-cli_${VERSION}_${OS}_${ARCH}.tar.gz" -o "akc-dcm-cli_${VERSION}_${OS}_${ARCH}.tar.gz"

tar -xzf "akc-dcm-cli_${VERSION}_${OS}_${ARCH}.tar.gz"

mv "dcm" /usr/local/bin/dcm

chmod +x /usr/local/bin/dcm

rm "akc-dcm-cli_${VERSION}_${OS}_${ARCH}.tar.gz"

echo "dcm version: $(dcm version)"

