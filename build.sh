#!/usr/bin/env bash

podman build -t jwt-firebase .

podman run --name jwt-firebase-build jwt-firebase sh -c "luarocks make && luarocks pack kong-plugin-jwt-firebase"
podman cp jwt-firebase-build:/home/app/kong-plugin-jwt-firebase-1.2.0-1.all.rock .
podman rm jwt-firebase-build
