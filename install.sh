#!/bin/sh
set -e
#
# This script provides a mechanism for easy installation of the
# cinder-docker-driver, use with curl or wget:
#  'curl -sSl https://https://raw.githubusercontent.com/j-griffith/cinder-docker-driver/master/install.sh | sh''
# or
#  'wget -qO- https://https://raw.githubusercontent.com/j-griffith/cinder-docker-driver/master/install.sh | sh'

BIN_NAME=cinder-docker-driver
DRIVER_URL="https://github.com/j-griffith/cinder-docker-driver/releases/download/v0.8/cinder-docker-driver"
BIN_DIR="/usr/bin"

do_install() {
sudo mkdir -p /var/lib/cinder/dockerdriver
sudo mkdir -p /var/lib/cinder/mount
sudo curl -sSL -o $BIN_DIR/$BIN_NAME $DRIVER_URL
sudo chmod +x $BIN_DIR/$BIN_NAME
}

do_install
