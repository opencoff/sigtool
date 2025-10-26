#! /usr/bin/env bash

# Tool to regenerate protobuf code as needed
#
# - it tacks on a version number for use by the individual tools
# - it supports git and mercurial version#
#
# NB:
#   o the attempt at decoding dirty repo state for mercurial is
#     borked. It doesn't know about untracked files
#
# (c) 2016 Sudhi Herle
#
# License: GPLv2

# Relative path to protobuf sources
# e.g. "a.proto b.proto"
Protobufs="internal/pb/hdr.proto internal/pb/key.proto"

#set -x

# -- DO NOT CHANGE ANYTHING AFTER THIS --

Z=`basename $0`
PWD=`pwd`

Static=0
Dryrun=0
Prodver=""
Repover=""
Verbose=0
Go=`which go`
Arch=
Bindir=$PWD/bin
#e=echo

#set -x
# Go module proxy URL
GoModProxy="https://proxy.golang.org"
ProtobufRepo="google.golang.org/protobuf"
VTProtoRepo="github.com/planetscale/vtprotobuf"

# tools.go definition
Tools_go=./tools.go

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

# Fetch the latest version of the given tool
gettool_version_latest() {
    local mod=$1; shift
    local jq=`which jq`
    local curl=`which curl`

    [ -z "$jq" ]   && die "can't find jq; please install it"
    [ -z "$curl" ] && die "can't find curl; please install it"

    local ver=$($curl -s "${GoModProxy}/${mod}/@latest" | $jq .Version | tr -d '"' ) || die "can't run curl"
    echo $ver
}

show_tool_versions() {
    # Lets find the latest versions
    local pb_latest=$(gettool_version_latest $ProtobufRepo)
    local vt_latest=$(gettool_version_latest $VTProtoRepo)

    set -- $($Go list -m $ProtobufRepo)
    local pb_mod=$2

    set -- $($Go list -m $VTProtoRepo)
    local vt_mod=$2

    echo "$ProtobufRepo: $pb_mod [latest $pb_latest]"
    echo "$VTProtoRepo: $vt_mod [latest $vt_latest]"
    exit 0
}


getvcs_version() {
    local rev=
    local prodv=
    local git=`which git`
    local hg=`which hg`

    if [ -n "$git" ]; then
        local xrev=$(git describe --always --dirty --long --abbrev=12) || exit 1
        rev="git:$xrev"
        prodv=$(git tag --list | sort -V | tail -1)
    elif [ -n "$hg" ]; then
        local xrev=$(hg id --id) || exit 1
        local brev=${xrev%+}
        if [ "$brev" != "$xrev" ]; then
            rev="hg:${brev}+dirty"
        else
            rev="hg:${brev}"
        fi
        prodv=$(hg log -r "branch(stable) and tag()" -T "{tags}\n" | sort -V | tail -1)
    else
        warn "no git or hg found; can't get VCS info"
        rev="UNKNOWN-VER"
    fi

    [ -n "$Prodver" ] && prodv=$Prodver

    echo "$rev $prodv"
    return 0
}

read -r Repover Prodver <<< $(getvcs_version)


usage() {
    declare -a progv=($Progs)
    declare n=${#progv[@]}
    declare pstr=

    for ((i=0; i < n; i++)); do
        local ent=${progv[$i]}
        local dir=${ent%%:*}
        local tool=${ent##*:}
        pstr=$(printf "$pstr\n\t%s $Prodver $Repover (from ./%s)" $tool $dir)
    done

    cat <<EOF
$0 - A Go tool that builds protobuf code as needed.

Usage: $0
       $0 [options]

Options:
    -h, --help          Show this help message and quit
    -n, --dry-run       Dry-run, don't actually build anything [False]
    -v, --verbose       Build verbosely (adds "-v" to go tooling) [False]
    --check-tools       Show the latest version of the protobuf tools
    --vet               Run "go vet" on modules named on the command line [False]
    -x                  Run in debug/trace mode [False]
    --print-arch        Print the target architecture and exit
EOF

    exit 0
}

host=`uname|tr '[A-Z]' '[a-z]'`

Tool=
args=
Printarch=0

#set -x
ac_prev=
for ac_option
do
  shift

  if [ -n "$ac_prev" ]; then
    eval "$ac_prev=\$ac_option"
    ac_prev=
    continue
  fi

  case "$ac_option" in
      -*=*) ac_optarg=`echo "$ac_option" | sed 's/[-_a-zA-Z0-9]*=//'` ;;
      *) ac_optarg= ;;
  esac


  case "$ac_option" in
        --help|-h|--hel|--he|--h)
            usage;
            ;;

        --vet)
            Tool=vet
            ;;

        --mod)
            Tool=mod
            ;;

        -v|--verbose)
            Verbose=1
            ;;

        --dry-run|-n)
            Dryrun=1
            ;;

        --debug|-x)
            set -x
            ;;

        --print-arch)
            Printarch=1
            ;;

        --check-tools)
            show_tool_versions
            ;;

        *) # first non option terminates option processing.
           # we gather all remaining args and bundle them up.
            args="$args $ac_option"
            for xx
            do
                args="$args $xx"
            done
            break
            ;;
  esac
done

[ $Dryrun  -gt 0 ] && e=echo

# let every error abort
set -e

# build a tool that runs on the host - if needed.
hosttool() {
    local out=$1
    local src=$2

    local name="$(basename $out)"

    # build per the go.mod file
    # build it and stash it in the hostdir
    echo "Building $name from $src .."
    $e $Go build -o $out $src || die "can't build $name"

    return 0
}

# check if a .proto file is newer than generated files
# Return "shell true" if files need to be regenerated
needs_regen() {
    local fn=$1; shift
    local base=${fn%.proto}
    local pbgo=${base}.pb.go
    local vtgo=${base}_vtproto.pb.go

    [ -f $pbgo -a  -f $vtgo ]          || return 0
    [ $fn -nt $pbgo -o $fn -nt $vtgo ] && return 0
    return 1
}

# protobuf gen
buildproto() {
    local pbgo=protoc-gen-go
    local vtgo=protoc-gen-go-vtproto
    local pbgo_src="$ProtobufRepo/cmd/$pbgo"
    local vtgo_src="$VTProtoRepo/cmd/$vtgo"
    local pc
    local args="$*"

    local pgen=$(type -p protoc)

    [ -z $pgen  ] && die "install protoc tools (protobuf on macports)"

    # Check to see if tools.go is present
    if [ ! -f $Tools_go ]; then
        cat <<_EOF > $Tools_go
//go:build tools

package tools

import (
    _ "google.golang.org/protobuf/cmd/protoc-gen-go"
    _ "github.com/planetscale/vtprotobuf/cmd/protoc-gen-go-vtproto"
)
_EOF

        $e $Go mod tidy
    fi

    local gogen=$Hostbindir/$pbgo
    local vtgen=$Hostbindir/$vtgo

    # install protoc-gen-go and vtproto tools locally; we want to
    # pin these tools to the specific versions in go.mod
    # tools.go captures the essential tooling dependency in go.mod
    [ -x $gogen ] || hosttool $gogen $pbgo_src
    [ -x $vtgen ] || hosttool $vtgen $vtgo_src

    local pwd=$(pwd)

    for f in $args; do
        needs_regen $f || continue

        $e $pgen  \
            --go_out=$pwd --plugin protoc-gen-go="$gogen" \
            --go_opt="paths=source_relative" \
            --go-vtproto_out=$pwd --plugin protoc-gen-go-vtproto="$vtgen" \
            --go-vtproto_opt="paths=source_relative,features=marshal+unmarshal+size"  \
             $f || die "can't generate protobuf output for $f .."
    done

    return 0
}


# the rest has to execute in the context of main shell (not funcs)

hostos=$($Go  env GOHOSTOS)      || exit 1
hostcpu=$($Go env GOHOSTARCH)    || exit 1

if [ $Printarch -gt 0 ]; then
    echo "$hostos-$hostcpu"
    exit 0
fi


# This is where build outputs go
Hostbindir=$Bindir/$hostos-$hostcpu
export PATH=$Hostbindir:$PATH

[ -d $Hostbindir ] || mkdir -p $Hostbindir


# Do Protobufs if needed
if [ -z "$Protobufs" ]; then
    warn "No protobuf files; nothing to do .."
    exit 0
fi


vflag=""
[ $Verbose -gt 0 ] && vflag="-v"

case $Tool in
    test)
        set -- $args
        $e $Go test $vflag "$@"
        ;;

    vet)
        set -- $args
        $e $Go vet $vflag "$@"
        ;;

    mod)
        set -- $args
        $e $Go mod $vflag "$@"
        ;;

    *) # Default is to build programs
        set +e
        buildproto $Protobufs
        set -e
esac

# vim: ft=sh:expandtab:ts=4:sw=4:tw=84:
