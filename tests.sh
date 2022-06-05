#! /usr/bin/env bash


# simple round-trip tests to verify the tool

arch=`./build --print-arch`
bin=./bin/$arch/sigtool
Z=`basename $0`

# workdir
tmpdir=/tmp/sigtool$$

die() {
    echo "$Z: $@" 1>&2
    echo "$Z: Test output in $tmpdir .." 1>&2
    exit 1
}


mkdir -p $tmpdir        || die "can't mkdir $tmpdir"
[ -x $bin ] || ./build  || die "Can't build sigtool for $arch"

# env name for reading the password
passenv=FOO

# this is the password for SKs
FOO=bar


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

# Now try with ssh ed25519 keys
keygen=`which ssh-keygen`
[ -z "$keygen" ] && die "can't find ssh-keygen"

ssk1=$tmpdir/ssk1
spk1=$ssk1.pub

ssk2=$tmpdir/ssk2
spk2=$ssk2.pub

# first generate two ssh keys
$keygen -q -C 'ssk1@foo' -t ed25519 -f $ssk1 -N "" 
$keygen -q -C 'ssk2@foo' -t ed25519 -f $ssk2 -N "" 

$bin s --no-password $ssk1 -o $sig $0 || die "can't sign with $ssk1"
$bin v -q $spk1 $sig $0               || die "can't verify with $spk2"

$bin e --no-password -o $encout $spk2 $0         || die "can't encrypt to $spk2 with $ssk1"
$bin d --no-password -o $decout $ssk2 $encout    || die "can't decrypt with $ssk2"

# cleanup state
rm -f $sig $encout $decout


# generate keys
$bin g -E FOO $bn            || die "can't gen keypair $pk, $sk"
$bin g -E FOO $bn            && die "overwrote prev keypair"
$bin g -E FOO --overwrite $bn    || die "can't force gen keypair $pk, $sk"
$bin g -E FOO $bn2               || die "can't force gen keypair $pk2, $sk2"

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

# Only delete if everything worked
echo "$Z: All tests pass!"
rm -rf $tmpdir

# vim: tw=100 sw=4 ts=4 expandtab
