#!/bin/bash
set -euo pipefail

node "$(dirname "$0")/scripts/build.mjs"
