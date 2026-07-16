// Command server is the go-0.13-echo4 interop harness server (CONTRACT.md):
// it exposes exactly one protected operation over HTTP, enforced by the
// shipped Echo adapters of valiss-go 0.13 (contrib/echoauth for signed mode,
// contrib/echosig for message mode). The entry exists to exercise the
// adapters, so the middlewares are the enforcement path; the harness only
// layers what the interop contract demands and the adapters do not produce:
//
//   - a custom echo.HTTPErrorHandler that renders the *echo.HTTPError the
//     adapters return as the contract's {"ok":false,"reason":<§7>} JSON;
//   - a request-rewriting middleware in message mode that makes
//     httpsig.Audience derive the suite's logical sink audience, because the
//     receiver pins the expected audience to the transport address with no
//     override;
//   - the allowlist check on the message chain's account, in the handler,
//     which is where the library places revocation for message receivers
//     (valiss.MessageClaims.Account documents exactly this pattern).
//
// Accept answers 200 with the contract's accept JSON; reject answers 401
// with the reject JSON, carrying the valiss-chain: required header on
// chainless message tokens (stamped by echosig itself, before the error
// handler writes). It prints "ready <addr>" once listening and exits
// cleanly on SIGTERM.
package main

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"log"
	"net"
	"net/http"
	"os"
	"os/signal"
	"strings"
	"syscall"

	"github.com/labstack/echo/v4"

	"valiss.dev/valiss"
	"valiss.dev/valiss/contrib/echoauth"
	"valiss.dev/valiss/contrib/echosig"
	"valiss.dev/valiss/contrib/httpauth"

	"github.com/valiss-dev/interop/harness/go-0.13-echo4/internal/reason"
	"github.com/valiss-dev/interop/harness/go-0.13-echo4/internal/wire"
)

func main() {
	log.SetFlags(0)
	log.SetPrefix("server: ")

	var (
		transport = flag.String("transport", "http", "transport to serve: this entry serves http only")
		addr      = flag.String("addr", "127.0.0.1:0", "HOST:PORT to listen on")
		operator  = flag.String("operator", "", "file with the pinned operator public key")
		allowlist = flag.String("allowlist", "", "file with the accepted account-token ids, one per line")
		mode      = flag.String("mode", "signed", "verification mode: signed or message")
	)
	flag.Parse()

	if *transport != "http" {
		log.Fatalf("unsupported transport %q: this entry serves http only", *transport)
	}
	if *operator == "" || *allowlist == "" {
		log.Fatal("--operator and --allowlist are required")
	}
	operatorRaw, err := os.ReadFile(*operator)
	if err != nil {
		log.Fatalf("read operator key: %v", err)
	}
	operatorPub := strings.TrimSpace(string(operatorRaw))

	allow, err := valiss.LoadAllowlistFile(*allowlist)
	if err != nil {
		log.Fatalf("load allowlist: %v", err)
	}

	e := echo.New()
	e.HTTPErrorHandler = contractErrors

	switch *mode {
	case "signed":
		// The fixture tokens carry no HTTP extension claim, and the interop
		// contract has no extension dimension, so the fail-closed default
		// (deny extensionless tokens) is relaxed with the adapter's own
		// option.
		verifier := valiss.NewVerifier(operatorPub, allow,
			valiss.WithReplayCache(valiss.NewMemoryReplayCache()))
		e.Use(echoauth.NewMiddleware(verifier, httpauth.AllowMissingExtension()))
		e.POST(wire.InvokePath, acceptSigned)
	case "message":
		// No httpsig.WithChainCache: a cache would let a bare token reuse a
		// chain negotiated by an earlier request, and the suite's
		// bare-signals-negotiation scenario asserts the no_chain rejection.
		e.Use(sinkAudience)
		e.Use(echosig.NewMiddleware(operatorPub))
		e.POST(wire.InvokePath, acceptMessage(allow))
	default:
		log.Fatalf("unknown mode %q", *mode)
	}

	lis, err := net.Listen("tcp", *addr)
	if err != nil {
		log.Fatalf("listen %s: %v", *addr, err)
	}

	sigs := make(chan os.Signal, 1)
	signal.Notify(sigs, syscall.SIGTERM, syscall.SIGINT)

	httpSrv := &http.Server{Handler: e}
	go func() {
		if err := httpSrv.Serve(lis); err != nil && !errors.Is(err, http.ErrServerClosed) {
			log.Fatalf("serve: %v", err)
		}
	}()
	fmt.Printf("ready %s\n", lis.Addr())
	<-sigs
	if err := httpSrv.Shutdown(context.Background()); err != nil {
		log.Fatalf("shutdown: %v", err)
	}
}

// acceptSigned renders the contract accept for a request echoauth
// authenticated; the middleware turned every other request into an
// *echo.HTTPError before it got here.
func acceptSigned(c echo.Context) error {
	id, ok := echoauth.IdentityFrom(c)
	if !ok {
		return c.JSON(http.StatusUnauthorized, wire.Reject{Reason: "missing"})
	}
	var user *string
	if id.User != nil {
		user = &id.User.Name
	}
	return c.JSON(http.StatusOK, wire.Accept{OK: true, Tenant: id.Account.Name, User: user})
}

// acceptMessage renders the contract accept for a message echosig verified,
// after holding the chain's account to the same allowlist signed mode
// enforces. The library places revocation with the receiver (message
// verification itself is offline), so this check is the documented
// integration point, not a bypass of adapter code.
func acceptMessage(allow valiss.Allowlist) echo.HandlerFunc {
	return func(c echo.Context) error {
		claims, ok := echosig.MessageFrom(c)
		if !ok {
			return c.JSON(http.StatusUnauthorized, wire.Reject{Reason: "missing"})
		}
		if !allow.Allowed(claims.Account.ID) {
			return c.JSON(http.StatusUnauthorized, wire.Reject{Reason: "not_allowlisted"})
		}
		return c.JSON(http.StatusOK, wire.Accept{OK: true, Tenant: claims.Account.Name, User: &claims.User.Name})
	}
}

// sinkAudience makes the shipped receiver expect the interop suite's
// logical audience. httpsig.Audience derives the expected audience from the
// request's Host and URL path, and the receiver appends that binding after
// every caller option, so no echosig/httpsig option can pin the
// scenarios.yaml audience "interop://sink". Rewriting the audience-bearing
// fields is safe here: Echo routed on the original path before Use
// middlewares run, and nothing downstream reads Host or the path.
func sinkAudience(next echo.HandlerFunc) echo.HandlerFunc {
	return func(c echo.Context) error {
		c.Request().Host = wire.SinkAudience
		c.Request().URL.Path = ""
		return next(c)
	}
}

// contractErrors renders every rejection as the contract's reject JSON with
// its §7 reason code. echoauth and echosig surface rejections as
// *echo.HTTPError carrying the verification error string (or echosig's
// fixed chain-required line) as the message, which the reason table reduces
// to the code. Headers already stamped on the response survive the JSON
// write, including the valiss-chain: required signal echosig sets before
// returning. Anything that is not an *echo.HTTPError with a string message
// still answers 401: verification failures must never widen access.
func contractErrors(err error, c echo.Context) {
	if c.Response().Committed {
		return
	}
	status := http.StatusUnauthorized
	msg := err.Error()
	if herr, ok := errors.AsType[*echo.HTTPError](err); ok {
		status = herr.Code
		if s, ok := herr.Message.(string); ok {
			msg = s
		}
	}
	if err := c.JSON(status, wire.Reject{Reason: reason.Code(msg)}); err != nil {
		log.Printf("write reject: %v", err)
	}
}
