# The runtime of the Linux screenshot tour and of the mockup renderer: Xvfb with Mesa's
# software renderer, xdotool, ImageMagick, and a headless Chromium (Debian's deb).
#   docker build -t apassy-ui-tour scripts/ui-review
FROM debian:trixie
ENV DEBIAN_FRONTEND=noninteractive
RUN apt-get update -q && apt-get install -y -q --no-install-recommends \
    xvfb x11-utils xdotool imagemagick libgl1-mesa-dri libgl1 libegl1 libglx-mesa0 \
    libxkbcommon-x11-0 libxkbcommon0 libxcursor1 libxrandr2 libxi6 libx11-xcb1 libwayland-client0 \
    dbus dbus-x11 gnome-keyring libsecret-tools polkitd pkexec \
    chromium fonts-dejavu-core fonts-liberation2 python3 python3-websocket ca-certificates procps \
    && rm -rf /var/lib/apt/lists/*
RUN useradd -m -u 1000 -s /bin/bash tour
