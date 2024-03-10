#! /usr/bin/env bash
# simple round-trip tests to verify the tool
# Usage:
#    $0 [bin=/path/to/sigtool] [tmpdir=/path/to/workdir]

Z=`basename $0`
die() {
    echo "$Z: $@" 1>&2
    echo "$Z: Test output in $tmpdir .." 1>&2
    exit 1
}

# cmd line args processing
for a in $*; do
    key=${a%=*}
    val=${a#*=}
    case $key in
        bin)
            bin=$val
            ;;

        tmpdir)
            tmpdir=$val
            ;;

        *)
            echo "Ignoring $key .."
            ;;
    esac
done

if [ -z "$bin" ]; then
    arch=`./build --print-arch`
    bin=./bin/$arch/sigtool

    [ -x $bin ] || ./build || die "can't find & build sigtool"
fi

[ -z "$tmpdir" ] && tmpdir=/tmp/sigtool$$

mkdir -p $tmpdir        || die "can't mkdir $tmpdir"

# env name for reading the password
passenv=FOO

# this is the password for SKs
FOO=bar


#trap "rm -rf $tmpdir" EXIT

bn=$tmpdir/foo
sig=$tmpdir/$Z.sig
pk=$bn.pub
sk=$bn.key
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

# extract the pk string
spk1_str=$(cat $spk1 | awk '{ print $2 }')

$bin s --no-password $ssk1 -o $sig $0       || die "can't sign with $ssk1"
$bin v -q $spk1 $sig $0                     || die "can't verify with $spk2"
$bin v -q $spk1_str $sig $0                 || die "can't verify with $spk2_str"

$bin e --no-password -o $encout $spk2 $0         || die "can't encrypt to $spk2 with $ssk1"
$bin d --no-password -o $decout $ssk2 $encout    || die "can't decrypt with $ssk2"

# cleanup state
rm -f $sig $encout $decout

# generate keys
$bin g -E FOO $bn                || die "can't gen keypair $pk, $sk"
$bin g -E FOO $bn 2>/dev/null    && die "overwrote prev keypair"
$bin g -E FOO --overwrite $bn    || die "can't force gen keypair $pk, $sk"
$bin g -E FOO $bn2               || die "can't force gen keypair $pk2, $sk2"

# extract pk string
pk_str=$(cat $pk | grep 'pk:' | sed -e 's/^pk: //g')
pk2_str=$(cat $pk2 | grep 'pk:' | sed -e 's/^pk: //g')

# sign and verify
$bin s -E FOO $sk $0 -o $sig            || die "can't sign $0"
$bin v -q $pk $sig $0                   || die "can't verify signature of $0"
$bin v -q $pk_str $sig $0               || die "can't verify signature of $0"
$bin v -q $pk2 $sig $0 2>/dev/null && die "bad verification with wrong $pk2"
$bin v -q $pk2_str $sig $0 2>/dev/null && die "bad verification with wrong $pk2"

# encrypt/decrypt
$bin e -E FOO -o $encout $pk2 $0      || die "can't encrypt to $pk2"
$bin d -E FOO -o $decout $sk2 $encout || die "can't decrypt with $sk2"
cmp -s $decout $0                     || die "decrypted file mismatch with $0"

# now with sender verification
$bin e -E FOO --overwrite -o $encout -s $sk $pk2 $0      || die "can't sender-encrypt to $pk2"
$bin d -E FOO --overwrite -o $decout -v $pk $sk2 $encout || die "can't decrypt with $sk2"
cmp -s $decout $0                                        || die "decrypted file mismatch with $0"

# Only delete if everything worked
echo "$Z: All tests pass!"
rm -rf $tmpdir

# vim: tw=100 sw=4 ts=4 expandtab
