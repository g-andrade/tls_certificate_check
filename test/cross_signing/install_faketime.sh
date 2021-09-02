#!/usr/bin/env bash

set -eu

function is_installed {
    which $1 >/dev/null;
}


if is_installed faketime; then
    echo "faketime already installed"
    exit
fi

if is_installed brew; then
    brew install faketime # FIXME untested
    exit
fi

if is_installed apt-get; then
    DEBIAN_FRONTEND=noninteractive sudo apt-get --yes install faketime
    exit
fi

>&2 echo "I don't know how to install faketime in your system"
exit 1
