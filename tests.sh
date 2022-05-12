#! /usr/bin/env bash


# simple round-trip tests to verify the tool

arch=`./build --print-arch`
bin=./bin/$arch/sigtool
Z=`basename $0`

die() {
    echo "$Z: $@" 1>&2
    exit 1
}


[ -x $bin ] || ./build || die "Can't build sigtool for $arch"

# env name for reading the password
passenv=FOO

# this is the password for SKs
FOO=bar

# basename of keyfile
tmpdir=/tmp/sigtool$$
mkdir -p $tmpdir || die "can't mkdir $tmpdir"

#trap "rm -rf $tmpdir" EXIT

bn=$tmpdir/foo
pk=$bn.pub
sk=$bn.key
sig=$tmpdir/$Z.sig
bn2=$tmpdir/bar
pk2=$bn2.pub
sk2=$bn2.key

encout=$tmpdir/$Z.enc
decout=$tmpdir/$Z.dec

# exit on any failure
set -e

# generate keys
$bin g -E FOO $bn            || die "can't gen keypair $pk, $sk"
$bin g -E FOO $bn            && die "overwrote prev keypair"
$bin g -E FOO --overwrite $bn    || die "can't force gen keypair $pk, $sk"
$bin g -E FOO $bn2           || die "can't force gen keypair $pk2, $sk2"

# sign and verify
$bin s -E FOO $sk $0 -o $sig || die "can't sign $0"
$bin v -q $pk $sig $0        || die "can't verify signature of $0"
$bin v -q $pk2 $sig $0       && die "bad verification with wrong $pk2"

# encrypt/decrypt
$bin e -E FOO -o $encout $pk2 $0      || die "can't encrypt to $pk2"
$bin d -E FOO -o $decout $sk2 $encout || die "can't decrypt with $sk2"
cmp -s $decout $0                     || die "decrypted file mismatch with $0"

# now with sender verification
$bin e -E FOO --overwrite -o $encout -s $sk $pk2 $0      || die "can't sender-encrypt to $pk2"
$bin d -E FOO --overwrite -o $decout -v $pk $sk2 $encout || die "can't decrypt with $sk2"
cmp -s $decout $0                            || die "decrypted file mismatch with $0"



# vim: tw=100 sw=4 ts=4 expandtab
