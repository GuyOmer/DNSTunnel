#! /bin/bash

/Applications/Google\ Chrome.app/Contents/MacOS/Google\ Chrome \
  --proxy-server="socks5://127.0.0.1:1080" \
  --incognito \
  --no-first-run \
  --no-default-browser-check \
  --no-service-autorun \
  --no-experiments \
  --no-report-upload \
  --metrics-recording-only \
  --disable-background-networking \
  --disable-component-update \
  --disable-sync \
  --disable-google-services \
  --disable-client-side-phishing-detection \
  --disable-default-apps \
  --disable-domain-reliability \
  --disable-breakpad \
  --disable-features=OptimizationHints,Translate,ChromeWhatsNew \
  --user-data-dir=$(mktemp -d) \
  https://google.com