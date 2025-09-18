#!/bin/bash
set -e
cd $(git rev-parse --show-toplevel)

# remove previous, if exists localhost-ca.pem
sudo rm /etc/ca-certificates/trust-source/anchors/localhost-ca.pem || true
sudo update-ca-trust

# add new
sudo cp site/ca/cert.pem /etc/ca-certificates/trust-source/anchors/localhost-ca.pem
cd /etc/ca-certificates/trust-source/anchors
sudo update-ca-trust

# trust list | grep -B 10 -A 10  MyRootCA
