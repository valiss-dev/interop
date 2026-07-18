// Command gen mints the frozen interop fixture (see ../../CONTRACT.md):
// the pinned operator public key, the account-token allowlist, the creds
// files the scenarios name, and the message-mode payload. The nkey seeds are
// fixed constants so the trust domain is stable across regenerations; the
// committed output is the authority, and byte-reproducibility across runs is
// not required (tokens embed a fresh iat and a content-hash jti).
//
// The pin in go.mod tracks the current valiss Go reference: fixture/gen is
// bumped to each new library minor as it releases, so the committed fixture is
// always minted by the latest reference. Regeneration embeds a fresh iat and a
// content-hash jti into every token, so allowlist.txt and creds/* necessarily
// differ on every run; operator.pub (derived from a fixed seed) and the
// payloads are deterministic. A structural difference beyond the fresh iat/jti
// signals a wire-format change and is a review signal, not noise.
//
// Usage: go run . [OUTPUT_DIR]   (default: the fixture directory, resolved
// relative to this source file)
package main

import (
	"log"
	"os"
	"path/filepath"
	"runtime"
	"time"

	"github.com/nats-io/nkeys"

	"valiss.dev/valiss"
	"valiss.dev/valiss/creds"
)

// Fixed nkey seeds of the frozen interop trust domain. Generated once and
// hardcoded: every regeneration re-mints tokens under the same keys, so the
// committed operator.pub stays the pinned anchor.
const (
	// operatorSeed anchors the trust domain (operator.pub).
	operatorSeed = "SOAEZWKXWYMZN624LFX2VN3T2BR3GXRO4ZWYSPAVOUEF6IKHPBCGNWGUZM"
	// acmeSeed is the "acme" tenant: its account token's jti is allowlisted.
	acmeSeed = "SAAAIWESABJKJYVL4423XHRULVKQBPBWYAXZK267FW73EAWLKDPRJHG5EM"
	// betaSeed is the revoked tenant: a valid operator-signed chain whose
	// account-token jti is deliberately absent from allowlist.txt.
	betaSeed = "SAAPJS3U4HSIW7QFUZOHW446DNHBYHRDQ7VWTTTFFSYRIBYYSHTF3JUIGU"
	// aliceSeed is the "alice" user delegated by acme (and, in the revoked
	// creds, by beta).
	aliceSeed = "SUAMV54ERK3PCFFHT7PWIUWJC2LT65QPWDXG4ZJNTJ62OB3D4G5ANOUIIY"
	// strayUserSeed is a second user key that never matches any token
	// subject: wrongkey.creds pairs alice's token with this seed.
	strayUserSeed = "SUAKWZ2EINXJX67AN5QRFKMDRUACXA55I3ZCIDVTT3TU7HZCRR7SNBGDOY"
)

// expiredAt is the fixed exp of expired.creds' user token: safely in the
// past for any conceivable run of the matrix.
var expiredAt = time.Date(2020, 1, 1, 0, 0, 0, 0, time.UTC)

// helloPayload is the fixed message-mode payload (payloads/hello.bin).
var helloPayload = []byte("hello, valiss interop\n")

func main() {
	log.SetFlags(0)
	out := defaultOutputDir()
	if len(os.Args) > 1 {
		out = os.Args[1]
	}

	operator := keyPair(operatorSeed)
	acme := keyPair(acmeSeed)
	beta := keyPair(betaSeed)
	alice := keyPair(aliceSeed)

	operatorPub := publicKey(operator)
	alicePub := publicKey(alice)

	// The acme chain: allowlisted account token plus alice's user tokens
	// (signing, bearer, and already-expired variants).
	acmeToken, err := valiss.IssueAccount(operator, publicKey(acme), valiss.WithName("acme"))
	check(err, "issue acme account token")
	aliceToken, err := valiss.IssueUser(acme, alicePub, valiss.WithName("alice"))
	check(err, "issue alice user token")
	bearerToken, err := valiss.IssueUser(acme, alicePub, valiss.WithName("alice"), valiss.WithBearer())
	check(err, "issue alice bearer token")
	expiredToken, err := valiss.IssueUser(acme, alicePub, valiss.WithName("alice"), valiss.WithExpiry(expiredAt))
	check(err, "issue expired alice token")

	// The beta chain: structurally valid up to the operator, but its account
	// token's jti never enters the allowlist, so servers reject it as
	// not_allowlisted.
	betaToken, err := valiss.IssueAccount(operator, publicKey(beta), valiss.WithName("beta"))
	check(err, "issue beta account token")
	betaAliceToken, err := valiss.IssueUser(beta, alicePub, valiss.WithName("alice"))
	check(err, "issue beta-delegated alice token")

	acmeClaims, err := valiss.Decode(acmeToken)
	check(err, "decode acme account token")

	write(out, "operator.pub", operatorPub+"\n")
	write(out, "allowlist.txt", acmeClaims.ID+"\n")
	write(out, filepath.Join("creds", "account.creds"), creds.Format(creds.Creds{
		AccountToken: acmeToken,
		Seed:         []byte(acmeSeed),
	}))
	write(out, filepath.Join("creds", "user.creds"), creds.Format(creds.Creds{
		AccountToken: acmeToken,
		UserToken:    aliceToken,
		Seed:         []byte(aliceSeed),
	}))
	write(out, filepath.Join("creds", "bearer.creds"), creds.Format(creds.Creds{
		AccountToken: acmeToken,
		UserToken:    bearerToken,
	}))
	write(out, filepath.Join("creds", "revoked.creds"), creds.Format(creds.Creds{
		AccountToken: betaToken,
		UserToken:    betaAliceToken,
		Seed:         []byte(aliceSeed),
	}))
	write(out, filepath.Join("creds", "expired.creds"), creds.Format(creds.Creds{
		AccountToken: acmeToken,
		UserToken:    expiredToken,
		Seed:         []byte(aliceSeed),
	}))
	write(out, filepath.Join("creds", "wrongkey.creds"), creds.Format(creds.Creds{
		AccountToken: acmeToken,
		UserToken:    aliceToken,
		Seed:         []byte(strayUserSeed),
	}))
	write(out, filepath.Join("payloads", "hello.bin"), string(helloPayload))

	log.Printf("fixture written to %s", out)
}

// defaultOutputDir resolves the fixture directory (the parent of gen/)
// relative to this source file, so the generator writes in place no matter
// the working directory.
func defaultOutputDir() string {
	_, self, _, ok := runtime.Caller(0)
	if !ok {
		log.Fatal("cannot resolve the generator source location; pass the output dir explicitly")
	}
	return filepath.Dir(filepath.Dir(self))
}

func keyPair(seed string) nkeys.KeyPair {
	kp, err := nkeys.FromSeed([]byte(seed))
	check(err, "decode seed")
	return kp
}

func publicKey(kp nkeys.KeyPair) string {
	pub, err := kp.PublicKey()
	check(err, "derive public key")
	return pub
}

func write(dir, name, content string) {
	path := filepath.Join(dir, name)
	check(os.MkdirAll(filepath.Dir(path), 0o755), "create "+filepath.Dir(path))
	check(os.WriteFile(path, []byte(content), 0o644), "write "+path)
	log.Printf("wrote %s", path)
}

func check(err error, what string) {
	if err != nil {
		log.Fatalf("%s: %v", what, err)
	}
}
