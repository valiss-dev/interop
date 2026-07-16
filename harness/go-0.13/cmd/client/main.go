// Command client is the go-0.13 interop harness client (CONTRACT.md): it
// makes exactly one authenticated request and reports the raw outcome as one
// JSON line — {"status": <int|grpc-code-string>, "reason": <§7 code|null>,
// "identity": {...}|null, "chain_required": <bool>} — exiting 0 whether the
// server accepted or rejected; only infrastructure failures exit nonzero.
//
// In signed mode creds with a seed sign the request with it as given — even
// a seed that does not match the token subject is used verbatim, since the
// server's rejection is what the matrix tests; creds without a seed go out
// as bearer requests. Signing clients always attach a nonce: the --nonce
// value when fixed by the scenario, a fresh random one otherwise, because a
// replay-suppressing server (like this entry's) requires one on every signed
// request.
//
// In message mode the client mints a message token over the --payload bytes
// bound to --audience with the --ttl lifetime (negative mints one already
// expired), sending the --tamper-payload bytes instead when the scenario
// wants the checksum to miss. --chain picks the chain delivery: embedded in
// the token (default), detached in the valiss-chain-* request headers, none
// at all, or negotiate — bare first, retransmitted once with the detached
// headers when the response carries the valiss-chain: required signal, the
// final outcome reported.
package main

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"log"
	"net/http"
	"os"
	"time"

	"github.com/nats-io/nkeys"
	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/credentials/insecure"
	"google.golang.org/grpc/metadata"
	"google.golang.org/grpc/status"

	"valiss.dev/valiss"
	"valiss.dev/valiss/creds"

	"github.com/valiss-dev/interop/harness/go-0.13/internal/wire"
	"github.com/valiss-dev/interop/harness/go-0.13/interoppb"
)

// outcome is the client's one-line report.
type outcome struct {
	// Status is the HTTP status int or the canonical gRPC code string.
	Status any `json:"status"`
	// Reason is the server's §7 reject code; null on accept.
	Reason *string `json:"reason"`
	// Identity is the accepted identity {"tenant":..., "user":...|null};
	// null on reject.
	Identity *identity `json:"identity"`
	// ChainRequired reports whether the final response carried the
	// chain-negotiation signal (valiss-chain: required); omitted when false.
	ChainRequired bool `json:"chain_required,omitempty"`
}

type identity struct {
	Tenant string  `json:"tenant"`
	User   *string `json:"user"`
}

func main() {
	log.SetFlags(0)
	log.SetPrefix("client: ")

	var (
		transport = flag.String("transport", "http", "transport to call: http or grpc")
		addr      = flag.String("addr", "", "HOST:PORT of the server")
		credsPath = flag.String("creds", "", "valiss creds file from the fixture")
		nonce     = flag.String("nonce", "", "fixed replay nonce (default: a fresh random nonce per signed request)")
		mode      = flag.String("mode", "signed", "request mode: signed or message")
		audience  = flag.String("audience", "", "message-mode audience binding")
		payload   = flag.String("payload", "", "message-mode payload file")
		tamper    = flag.String("tamper-payload", "", "message-mode file sent instead of the checksummed --payload bytes")
		ttl       = flag.Duration("ttl", valiss.DefaultMessageTTL, "message-token lifetime; negative mints an already-expired token")
		chain     = flag.String("chain", "embedded", "message-mode chain delivery: embedded, detached, none, or negotiate")
	)
	flag.Parse()

	if *addr == "" || *credsPath == "" {
		log.Fatal("--addr and --creds are required")
	}
	c, err := creds.Load(*credsPath)
	if err != nil {
		log.Fatalf("load creds: %v", err)
	}

	var out outcome
	switch *mode {
	case "signed":
		out, err = signed(*transport, *addr, c, *nonce)
	case "message":
		out, err = message(*transport, *addr, c, messageOpts{
			audience:    *audience,
			payloadPath: *payload,
			tamperPath:  *tamper,
			ttl:         *ttl,
			chain:       *chain,
		})
	default:
		log.Fatalf("unknown mode %q", *mode)
	}
	if err != nil {
		log.Fatal(err)
	}
	line, err := json.Marshal(out)
	if err != nil {
		log.Fatalf("encode outcome: %v", err)
	}
	fmt.Println(string(line))
}

// signed makes one credential-signed (or bearer) request.
func signed(transport, addr string, c creds.Creds, nonce string) (outcome, error) {
	var subject nkeys.KeyPair
	if len(c.Seed) > 0 {
		kp, err := nkeys.FromSeed(c.Seed)
		if err != nil {
			return outcome{}, fmt.Errorf("creds seed: %w", err)
		}
		subject = kp
		if nonce == "" {
			nonce = valiss.NewNonce()
		}
	} else {
		// Bearer creds carry no signature, so a nonce would bind nothing.
		nonce = ""
	}

	switch transport {
	case "http":
		req, err := http.NewRequest(http.MethodPost, "http://"+addr+wire.InvokePath, nil)
		if err != nil {
			return outcome{}, err
		}
		if c.AccountToken != "" {
			req.Header.Set(valiss.HeaderAccountToken, c.AccountToken)
		}
		if c.UserToken != "" {
			req.Header.Set(valiss.HeaderUserToken, c.UserToken)
		}
		if subject != nil {
			if nonce != "" {
				req.Header.Set(valiss.HeaderNonce, nonce)
			}
			ctx := wire.HTTPRequestContext(req.Method, req.URL.Host, req.URL.Path, nonce)
			ts, sig, err := valiss.SignRequest(subject, time.Now(), ctx)
			if err != nil {
				return outcome{}, fmt.Errorf("sign request: %w", err)
			}
			req.Header.Set(valiss.HeaderTimestamp, ts)
			req.Header.Set(valiss.HeaderSignature, sig)
		}
		return doHTTP(req)
	case "grpc":
		md := metadata.MD{}
		if c.AccountToken != "" {
			md.Set(valiss.HeaderAccountToken, c.AccountToken)
		}
		if c.UserToken != "" {
			md.Set(valiss.HeaderUserToken, c.UserToken)
		}
		if subject != nil {
			if nonce != "" {
				md.Set(valiss.HeaderNonce, nonce)
			}
			ctx := wire.GRPCRequestContext(interoppb.Interop_Invoke_FullMethodName, nonce)
			ts, sig, err := valiss.SignRequest(subject, time.Now(), ctx)
			if err != nil {
				return outcome{}, fmt.Errorf("sign request: %w", err)
			}
			md.Set(valiss.HeaderTimestamp, ts)
			md.Set(valiss.HeaderSignature, sig)
		}
		return doGRPC(addr, md, nil)
	default:
		return outcome{}, fmt.Errorf("unknown transport %q", transport)
	}
}

// messageOpts is the message-mode request shape (the contract's client
// flags).
type messageOpts struct {
	audience    string
	payloadPath string
	// tamperPath, when set, names the bytes actually sent; the mint still
	// checksums the payloadPath bytes.
	tamperPath string
	// ttl is the minted token's lifetime; negative mints one already
	// expired.
	ttl time.Duration
	// chain is the delivery mode: embedded, detached, none, or negotiate.
	chain string
}

// message mints a per-message proof over the payload bytes bound to the
// audience and sends payload plus token, delivering the creds' chain the way
// opts.chain asks: embedded in the token, detached in the valiss-chain-*
// headers, not at all, or negotiated — bare first, one retransmit with the
// detached headers when the response signals valiss-chain: required.
func message(transport, addr string, c creds.Creds, opts messageOpts) (outcome, error) {
	if c.AccountToken == "" || c.UserToken == "" || len(c.Seed) == 0 {
		return outcome{}, errors.New("message mode requires bundle creds: account token, user token, and seed")
	}
	user, err := nkeys.FromSeed(c.Seed)
	if err != nil {
		return outcome{}, fmt.Errorf("creds seed: %w", err)
	}
	// The trust-domain epoch comes from the chain tokens, which must agree
	// on it (mirrors the contrib emitters' minter).
	accountIssuer, err := valiss.IssuerOf(c.AccountToken)
	if err != nil {
		return outcome{}, fmt.Errorf("creds account token: %w", err)
	}
	account, err := valiss.VerifyAccount(c.AccountToken, accountIssuer)
	if err != nil {
		return outcome{}, fmt.Errorf("creds account token: %w", err)
	}
	userClaims, err := valiss.VerifyUser(c.UserToken, account.Subject)
	if err != nil {
		return outcome{}, fmt.Errorf("creds user token: %w", err)
	}
	if account.Epoch != userClaims.Epoch {
		return outcome{}, fmt.Errorf("creds chain epochs disagree: account %d, user %d", account.Epoch, userClaims.Epoch)
	}

	var payload []byte
	if opts.payloadPath != "" {
		payload, err = os.ReadFile(opts.payloadPath)
		if err != nil {
			return outcome{}, fmt.Errorf("read payload: %w", err)
		}
	}
	// The checksum binds the --payload bytes; --tamper-payload swaps what
	// actually travels, so the server's payload binding must miss.
	send := payload
	if opts.tamperPath != "" {
		send, err = os.ReadFile(opts.tamperPath)
		if err != nil {
			return outcome{}, fmt.Errorf("read tamper payload: %w", err)
		}
	}

	mintOpts := []valiss.IssueOption{
		valiss.WithChecksum(valiss.Checksum(payload)),
		valiss.WithTTL(opts.ttl),
		valiss.WithEpoch(userClaims.Epoch),
	}
	if opts.chain == "embedded" {
		mintOpts = append(mintOpts, valiss.WithChain(c.AccountToken, c.UserToken))
	}
	if opts.audience != "" {
		mintOpts = append(mintOpts, valiss.WithAudience(opts.audience))
	}
	token, err := valiss.IssueMessage(user, mintOpts...)
	if err != nil {
		return outcome{}, fmt.Errorf("issue message token: %w", err)
	}

	// call performs the one request, attaching the detached chain headers
	// when asked; negotiate runs it bare and once more detached on the
	// signal.
	call := func(detached bool) (outcome, error) {
		switch transport {
		case "http":
			var body io.Reader
			if len(send) > 0 {
				body = bytes.NewReader(send)
			}
			req, err := http.NewRequest(http.MethodPost, "http://"+addr+wire.InvokePath, body)
			if err != nil {
				return outcome{}, err
			}
			req.Header.Set(valiss.HeaderMessageToken, token)
			if detached {
				req.Header.Set(valiss.HeaderChainAccountToken, c.AccountToken)
				req.Header.Set(valiss.HeaderChainUserToken, c.UserToken)
			}
			return doHTTP(req)
		case "grpc":
			md := metadata.MD{}
			md.Set(valiss.HeaderMessageToken, token)
			if detached {
				md.Set(valiss.HeaderChainAccountToken, c.AccountToken)
				md.Set(valiss.HeaderChainUserToken, c.UserToken)
			}
			return doGRPC(addr, md, send)
		default:
			return outcome{}, fmt.Errorf("unknown transport %q", transport)
		}
	}

	switch opts.chain {
	case "embedded", "none":
		return call(false)
	case "detached":
		return call(true)
	case "negotiate":
		out, err := call(false)
		if err != nil || !out.ChainRequired {
			return out, err
		}
		return call(true)
	default:
		return outcome{}, fmt.Errorf("unknown chain delivery %q", opts.chain)
	}
}

// doHTTP performs the one HTTP request and folds the response into the
// contract outcome, including whether it carried the chain-negotiation
// signal header.
func doHTTP(req *http.Request) (outcome, error) {
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return outcome{}, fmt.Errorf("request failed: %w", err)
	}
	defer resp.Body.Close()
	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return outcome{}, fmt.Errorf("read response: %w", err)
	}
	out := outcome{
		Status:        resp.StatusCode,
		ChainRequired: resp.Header.Get(valiss.HeaderChain) == valiss.ChainRequired,
	}
	fill(&out, body)
	return out, nil
}

// doGRPC performs the one gRPC call and folds the status into the contract
// outcome, reading the chain-negotiation signal from the trailing metadata.
// UNAVAILABLE means the server never answered: an infrastructure error, not
// an outcome.
func doGRPC(addr string, md metadata.MD, payload []byte) (outcome, error) {
	conn, err := grpc.NewClient(addr, grpc.WithTransportCredentials(insecure.NewCredentials()))
	if err != nil {
		return outcome{}, fmt.Errorf("dial: %w", err)
	}
	defer conn.Close()

	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	ctx = metadata.NewOutgoingContext(ctx, md)

	var trailer metadata.MD
	resp, err := interoppb.NewInteropClient(conn).Invoke(ctx,
		&interoppb.InvokeRequest{Payload: payload}, grpc.Trailer(&trailer))
	chainRequired := func() bool {
		if v := trailer.Get(valiss.HeaderChain); len(v) > 0 {
			return v[0] == valiss.ChainRequired
		}
		return false
	}
	if err == nil {
		out := outcome{Status: grpcCodeNames[codes.OK], ChainRequired: chainRequired()}
		fill(&out, []byte(resp.GetJson()))
		return out, nil
	}
	st, ok := status.FromError(err)
	if !ok || st.Code() == codes.Unavailable || st.Code() == codes.DeadlineExceeded {
		return outcome{}, fmt.Errorf("call failed: %w", err)
	}
	out := outcome{Status: grpcCodeNames[st.Code()], ChainRequired: chainRequired()}
	fill(&out, []byte(st.Message()))
	return out, nil
}

// fill parses a contract response body (accept or reject shape) into the
// outcome; a body in neither shape leaves reason and identity null.
func fill(out *outcome, body []byte) {
	var r wire.Response
	if err := json.Unmarshal(body, &r); err != nil {
		return
	}
	if r.OK {
		out.Identity = &identity{Tenant: r.Tenant, User: r.User}
		return
	}
	if r.Reason != "" {
		out.Reason = &r.Reason
	}
}

// grpcCodeNames renders codes in their canonical wire spelling, which the
// contract's "grpc code string" means.
var grpcCodeNames = map[codes.Code]string{
	codes.OK:                 "OK",
	codes.Canceled:           "CANCELLED",
	codes.Unknown:            "UNKNOWN",
	codes.InvalidArgument:    "INVALID_ARGUMENT",
	codes.DeadlineExceeded:   "DEADLINE_EXCEEDED",
	codes.NotFound:           "NOT_FOUND",
	codes.AlreadyExists:      "ALREADY_EXISTS",
	codes.PermissionDenied:   "PERMISSION_DENIED",
	codes.ResourceExhausted:  "RESOURCE_EXHAUSTED",
	codes.FailedPrecondition: "FAILED_PRECONDITION",
	codes.Aborted:            "ABORTED",
	codes.OutOfRange:         "OUT_OF_RANGE",
	codes.Unimplemented:      "UNIMPLEMENTED",
	codes.Internal:           "INTERNAL",
	codes.Unavailable:        "UNAVAILABLE",
	codes.DataLoss:           "DATA_LOSS",
	codes.Unauthenticated:    "UNAUTHENTICATED",
}
