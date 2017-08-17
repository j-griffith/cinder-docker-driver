#!/bin/sh
set -e

BIN_NAME="cinder-docker-driver"
DRIVER_URL="https://github.com/ju-la-berger/cinder-docker-driver/releases/download/v0.13-rc5/cinder-docker-driver.linux-amd64"
BIN_DIR="/usr/bin"

do_install () {
    mkdir -p /var/lib/cinder/dockerdriver
    mkdir -p /var/lib/cinder/mount
    rm ${BIN_DIR}/${BIN_NAME} || true
    curl -sSL -o ${BIN_DIR}/${BIN_NAME} ${DRIVER_URL}
    chmod +x ${BIN_DIR}/${BIN_NAME}
    echo "
    [Unit]
    Description=\"Cinder Docker Plugin daemon\"
    Before=docker.service
    Requires=cinder-docker-driver.service

    [Service]
    TimeoutStartSec=0
    ExecStart=/usr/bin/cinder-docker-driver &

    [Install]
    WantedBy=docker.service" >/etc/systemd/system/cinder-docker-driver.service

    chmod 644 /etc/systemd/system/cinder-docker-driver.service
    systemctl daemon-reload
    systemctl enable cinder-docker-driver
}

do_install
