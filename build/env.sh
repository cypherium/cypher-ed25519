#!/bin/sh

set -e

if [ ! -f "build/env.sh" ]; then
    echo "$0 must be run from the root of the repository."
    exit 2
fi

# Create fake Go workspace if it doesn't exist yet.
workspace="$PWD/build/_workspace"
root="$PWD"
cphdir="$workspace/src/github.com/cypherium/cypherBFT"
wrkdir="$workspace/src/github.com/cypherium"
if [ ! -d "$wrkdir" ]; then
    mkdir -p "$wrkdir"
    cd "$wrkdir"
    ln -s  ../../../../../  ./cypherBFT
#    cp `ls  ../../../../../ | grep -v "_workspace" | awk '{print i$0}' i='../../../../../'` .
    cd "$root"
fi

# Set up the environment to use the workspace.
GOPATH="$workspace"
export GOPATH

# Run the command inside the workspace.
cd "$cphdir"
PWD="$cphdir"

# Launch the arguments with the configured environment.
exec "$@"
