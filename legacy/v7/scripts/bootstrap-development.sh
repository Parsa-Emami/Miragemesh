#!/usr/bin/env bash
set -euo pipefail

# Run from the repository root after verifying the GitHub owner/module namespace.
# This script intentionally performs source bootstrap only; infrastructure credentials are never generated.

composer create-project laravel/laravel:^13.0 apps/control-plane
mkdir -p services/sensor
(cd services/sensor && go mod init github.com/Parsa-Emami/miragemesh/sensor)

printf "\nBootstrap command sequence completed. Review generated files, pin/lock dependencies, then run repository validation before commit.\n"
