# Ed25519 Signature Hash Parameter Analysis

## Issue Description
When using `crypto.SHA512` instead of `crypto.Hash(0)` in `sign.go:SignMessage()`,
all tests in `sign_test.go` fail with verification errors.

## Root Cause: Signature Scheme Mismatch

### The Two Ed25519 Variants

Go's `crypto/ed25519` package supports two signature schemes:

1. **Plain Ed25519** (`crypto.Hash(0)`)
   - Standard Ed25519 signature scheme
   - Takes any message and signs it directly
   - Used with: `PrivateKey.Sign(rand, message, crypto.Hash(0))`
   - Verified with: `ed25519.Verify(publicKey, message, sig)`

2. **Ed25519ph** (`crypto.SHA512`)
   - Pre-hashed variant of Ed25519
   - Different signature algorithm/format
   - Message is expected to be a SHA-512 hash
   - Used with: `PrivateKey.Sign(rand, hash, crypto.SHA512)`
   - Verified with: `ed25519.VerifyWithOptions(publicKey, hash, sig, &Options{Hash: crypto.SHA512})`

### Current Implementation

**Signing in `sign.go:40-50`:**
```go
// Pre-hash the message
h := sha512.New()
h.Write([]byte(_Sigtool_sign_prefix))
h.Write(msg)
ck := h.Sum(hb[:0])[:]

// Sign with plain Ed25519
x := Ed.PrivateKey(sk.sk)
sig, err := x.Sign(rand.Reader, ck, crypto.Hash(0))
```

**Verification in `sign.go:113-122`:**
```go
// Pre-hash the message
h := sha512.New()
h.Write([]byte(_Sigtool_sign_prefix))
h.Write(msg)
ck := h.Sum(hb[:0])[:]

// Verify with plain Ed25519
x := Ed.PublicKey(pk.pk)
return Ed.Verify(x, ck, sig)
```

**Status:** ✅ **WORKS** - Both use plain Ed25519

### What Happens With crypto.SHA512

**Signing:**
```go
sig, err := x.Sign(rand.Reader, ck, crypto.SHA512)  // Uses Ed25519ph
```

**Verification:**
```go
return Ed.Verify(x, ck, sig)  // Still uses plain Ed25519
```

**Status:** ❌ **FAILS** - Signature scheme mismatch!

The signature is created using Ed25519ph, but verification attempts to use
plain Ed25519. These are incompatible signature schemes.

### Test Failure Evidence

```
$ go test -v -run TestSignRandBuf
=== RUN   TestSignRandBuf
    utils_test.go:36: /home/user/sigtool/sign_test.go: 58: Assertion failed: verify: failed
--- FAIL: TestSignRandBuf (0.00s)
```

The test fails at `sign_test.go:58` which asserts that verification succeeds:
```go
ok, err := pk.VerifyMessage(ck[:], sig)
assert(err == nil, "verify: %s", err)
assert(ok, "verify: failed")  // ← FAILS HERE
```

## Why crypto.Hash(0) is Correct

The current implementation using `crypto.Hash(0)` is correct because:

1. **Message is already pre-hashed**: The code computes `SHA512(prefix + msg)` before signing
2. **Plain Ed25519 compatibility**: Standard `Ed.Verify()` only works with plain Ed25519
3. **No double hashing**: Using `crypto.Hash(0)` tells Ed25519 to sign the pre-hashed value as-is
4. **Signing and verification match**: Both sides use the same scheme

## To Use crypto.SHA512 (Not Recommended)

Both signing AND verification would need changes:

**In `sign.go:50`:**
```go
// Change from:
sig, err := x.Sign(rand.Reader, ck, crypto.Hash(0))

// To:
sig, err := x.Sign(rand.Reader, ck, crypto.SHA512)
```

**In `sign.go:122`:**
```go
// Change from:
return Ed.Verify(x, ck, sig)

// To:
opts := &Ed.Options{Hash: crypto.SHA512}
err := Ed.VerifyWithOptions(x, ck, sig, opts)
return err == nil
```

## Recommendation

**Keep using `crypto.Hash(0)`** because:
- ✅ Current implementation is correct and secure
- ✅ Uses standard Ed25519 (widely supported)
- ✅ Already pre-hashes messages with SHA-512 for domain separation
- ✅ No benefit to switching to Ed25519ph in this context
- ✅ Simpler verification code

## References

From `go doc crypto/ed25519.PrivateKey.Sign`:
> If opts.HashFunc() is crypto.SHA512, the pre-hashed variant Ed25519ph is
> used and message is expected to be a SHA-512 hash, otherwise opts.HashFunc()
> must be crypto.Hash(0) and the message must not be hashed, as Ed25519
> performs two passes over messages to be signed.

From `go doc crypto/ed25519.VerifyWithOptions`:
> If opts.Hash is crypto.SHA512, the pre-hashed variant Ed25519ph is used

## Conclusion

The `crypto.Hash(0)` parameter is **mandatory** in the current implementation
because the verification code uses `Ed.Verify()` which only supports plain
Ed25519. Changing to `crypto.SHA512` requires changing both signing and
verification to use the Ed25519ph variant, offering no practical benefit.
