#!/bin/bash

export OAUTH_CLIENT="0f33052d9fee8303c36e"
export OAUTH_SECRET="e57d898182a2f68d9a44c1c69a892a1b66e85be0"
export SESSION_KEY="/var/artipie/keys/artipie.der"
export ARTIPIE_SESSION_KEY="/var/artipie/keys/artipie-priv.der"
export TKN_KEY="" #variable must be set for artipie/front for future GitHub API integration

docker-compose build
docker-compose pull artipie
docker-compose down
docker-compose up -d
