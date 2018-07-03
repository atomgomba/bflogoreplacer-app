#!/bin/bash
FONTS_ZIP="/tmp/bf-fonts.zip"
FONTS_DIR="./static/fonts"
wget -nc -O ${FONTS_ZIP} https://github.com/betaflight/betaflight-configurator/archive/master.zip
mkdir -p ${FONTS_DIR}
unzip -j ${FONTS_ZIP} *.mcm -d ${FONTS_DIR}
