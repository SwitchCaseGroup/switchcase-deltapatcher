#!/bin/bash

DIST="$(pwd)/dist"
if [[ ! -z $CI  ]]
then
  debuild -us -uc --lintian-opts --profile debian "$@"
else
  echo "install dependencies..."
  export DEBIAN_FRONTEND=noninteractive
  apt-get update
  apt-get install -yq git-buildpackage
  apt-get install -yq python3-all
  apt-get install -yq equivs devscripts
  # mk-build-deps --install --root-cmd sudo --remove
  # newer versions of mk-build-deps automatically specify -y for tool
  mk-build-deps -t "apt-get -o Debug::pkgProblemResolver=yes -y --no-install-recommends" --install --remove
  #debuild -us -uc --lintian-opts --profile debian "$@"
  debuild -us -uc
  #gbp buildpackage --lintian-opts --profile debian "$@"
fi
