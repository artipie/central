#!/bin/bash

set -e

out="$1"
if [[ -z "$out" ]]; then
  out="$PWD"
fi

openssl genrsa -out "${out}/artipie.pem" 2048
openssl rsa -in "${out}/artipie.pem" -outform DER -pubout -out "${out}/artipie.der"
openssl pkcs8 -topk8 -nocrypt -in "${out}/artipie.pem" -outform DER -out "${out}/artipie-priv.der"
