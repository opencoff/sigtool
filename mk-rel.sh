#! /usr/bin/env bash

Z=`basename $0`
die() {
    echo "$Z: $@" 1>&2
    exit 0
}

warn() {
    echo "$Z: $@" 1>&2
}

case $BASH_VERSION in
    4.*|5.*) ;;

    *) die "I need bash 4.x to run!"
        ;;
esac

Rel=$PWD/releases

pkgit() {
    local os=$1
    local cpu=$2
    local rev=$3
    local arch="$os-$cpu"
    local tgz="$Rel/sigtool-${rev}_${arch}.tar.gz"
    local bindir=./bin/$arch
    local bin=sigtool

    if [ "$os" = "windows" ]; then
        bin=${bin}.exe
    fi

    ./build -V $rev -s -a $arch || die "can't build $arch"
    (cd $bindir && tar cf - $bin)  | gzip -9 > $tgz || die "can't tar $tgz"
}

xrev=$(git describe --always --dirty --abbrev=12) || exit 1
if echo $xrev | grep -q dirty; then
    #die "won't build releases; repo dirty!"
    true
fi

os="linux windows openbsd darwin"
arch="amd64 arm64"

mkdir -p $Rel

for xx in $os; do
    for yy in $arch; do
        pkgit $xx $yy $xrev
    done
done
