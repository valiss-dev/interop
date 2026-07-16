// Command client is the go-0.13rc1 interop harness client (CONTRACT.md): it
// makes exactly one authenticated request and reports the raw outcome as one
// JSON line — {"status": <int|grpc-code-string>, "reason": <§7 code|null>,
// "identity": {...}|null} — exiting 0 whether the server accepted or
// rejected; only infrastructure failures exit nonzero.
//
// In signed mode creds with a seed sign the request with it as given — even
// a seed that does not match the token subject is used verbatim, since the
// server's rejection is what the matrix tests; creds without a seed go out
// as bearer requests. Signing clients always attach a nonce: the --nonce
// value when fixed by the scenario, a fresh random one otherwise, because a
// replay-suppressing server (like this entry's) requires one on every signed
// request. In message mode the client mints a message token over the
// --payload bytes bound to --audience, with the creds' chain embedded.
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

	"github.com/valiss-dev/interop/harness/go-0.13rc1/internal/wire"
	"github.com/valiss-dev/interop/harness/go-0.13rc1/interoppb"
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
		out, err = message(*transport, *addr, c, *audience, *payload)
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

// message mints a per-message proof over the payload bytes bound to the
// audience, with the creds' chain embedded, and sends payload plus token.
func message(transport, addr string, c creds.Creds, audience, payloadPath string) (outcome, error) {
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
	if payloadPath != "" {
		payload, err = os.ReadFile(payloadPath)
		if err != nil {
			return outcome{}, fmt.Errorf("read payload: %w", err)
		}
	}

	mintOpts := []valiss.IssueOption{
		valiss.WithChecksum(valiss.Checksum(payload)),
		valiss.WithTTL(valiss.DefaultMessageTTL),
		valiss.WithEpoch(userClaims.Epoch),
		valiss.WithChain(c.AccountToken, c.UserToken),
	}
	if audience != "" {
		mintOpts = append(mintOpts, valiss.WithAudience(audience))
	}
	token, err := valiss.IssueMessage(user, mintOpts...)
	if err != nil {
		return outcome{}, fmt.Errorf("issue message token: %w", err)
	}

	switch transport {
	case "http":
		var body io.Reader
		if len(payload) > 0 {
			body = bytes.NewReader(payload)
		}
		req, err := http.NewRequest(http.MethodPost, "http://"+addr+wire.InvokePath, body)
		if err != nil {
			return outcome{}, err
		}
		req.Header.Set(valiss.HeaderMessageToken, token)
		return doHTTP(req)
	case "grpc":
		md := metadata.MD{}
		md.Set(valiss.HeaderMessageToken, token)
		return doGRPC(addr, md, payload)
	default:
		return outcome{}, fmt.Errorf("unknown transport %q", transport)
	}
}

// doHTTP performs the one HTTP request and folds the response into the
// contract outcome.
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
	out := outcome{Status: resp.StatusCode}
	fill(&out, body)
	return out, nil
}

// doGRPC performs the one gRPC call and folds the status into the contract
// outcome. UNAVAILABLE means the server never answered: an infrastructure
// error, not an outcome.
func doGRPC(addr string, md metadata.MD, payload []byte) (outcome, error) {
	conn, err := grpc.NewClient(addr, grpc.WithTransportCredentials(insecure.NewCredentials()))
	if err != nil {
		return outcome{}, fmt.Errorf("dial: %w", err)
	}
	defer conn.Close()

	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	ctx = metadata.NewOutgoingContext(ctx, md)

	resp, err := interoppb.NewInteropClient(conn).Invoke(ctx, &interoppb.InvokeRequest{Payload: payload})
	if err == nil {
		out := outcome{Status: grpcCodeNames[codes.OK]}
		fill(&out, []byte(resp.GetJson()))
		return out, nil
	}
	st, ok := status.FromError(err)
	if !ok || st.Code() == codes.Unavailable || st.Code() == codes.DeadlineExceeded {
		return outcome{}, fmt.Errorf("call failed: %w", err)
	}
	out := outcome{Status: grpcCodeNames[st.Code()]}
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
