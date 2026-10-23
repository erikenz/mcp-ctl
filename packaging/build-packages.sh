#!/usr/bin/env bash
# Build a .deb and a .rpm around an already-built binary.
#
#   build-packages.sh <version> <deb-arch> <rpm-arch> <binary> <out-dir>
#
# The binary is static, so neither package declares a dependency: they install
# on any distribution of that architecture.
set -euo pipefail

version=$1
deb_arch=$2
rpm_arch=$3
binary=$4
out=$5

mkdir -p "$out"
work=$(mktemp -d)
trap 'rm -rf "$work"' EXIT

maintainer="Erik <46247842+erikenz@users.noreply.github.com>"
homepage="https://github.com/erikenz/mcp-ctl"
summary="One config file for all your MCP servers"

# --- .deb -------------------------------------------------------------------
root="$work/deb"
install -D -m 755 "$binary" "$root/usr/bin/mcp-ctl"
mkdir -p "$root/DEBIAN"
cat > "$root/DEBIAN/control" <<EOF
Package: mcp-ctl
Version: $version
Section: utils
Priority: optional
Architecture: $deb_arch
Maintainer: $maintainer
Homepage: $homepage
Description: $summary
 Secrets from a password manager, stdio for local editors, and one
 authenticated HTTP endpoint for remote agents.
EOF
dpkg-deb --root-owner-group --build "$root" "$out/mcp-ctl_${version}_${deb_arch}.deb" > /dev/null

# --- .rpm -------------------------------------------------------------------
mkdir -p "$work/rpm/BUILD" "$work/rpm/SPECS"
install -m 755 "$binary" "$work/rpm/BUILD/mcp-ctl"
cat > "$work/rpm/SPECS/mcp-ctl.spec" <<EOF
Name: mcp-ctl
Version: $version
Release: 1
Summary: $summary
License: MIT
URL: $homepage
BuildArch: $rpm_arch
%description
Secrets from a password manager, stdio for local editors, and one
authenticated HTTP endpoint for remote agents.
%install
install -D -m 755 %{_builddir}/mcp-ctl %{buildroot}/usr/bin/mcp-ctl
%files
/usr/bin/mcp-ctl
EOF
rpmbuild -bb --quiet \
  --define "_topdir $work/rpm" \
  --define "_rpmdir $work/rpm/RPMS" \
  "$work/rpm/SPECS/mcp-ctl.spec" > /dev/null
find "$work/rpm/RPMS" -name '*.rpm' -exec mv {} "$out/mcp-ctl-${version}-1.${rpm_arch}.rpm" \;

echo "built:"
ls -1 "$out"
