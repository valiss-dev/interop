// Command server is the go-0.13-gin1 interop harness server (CONTRACT.md):
// it exposes exactly one protected operation over HTTP, enforced by the
// shipped Gin adapters of valiss-go 0.13 (contrib/ginauth for signed mode,
// contrib/ginsig for message mode). The entry exists to exercise the
// adapters, so the middlewares are the enforcement path; the harness only
// layers what the interop contract demands and the adapters do not produce:
//
//   - a response-shaping middleware that rewrites the adapters' plain-text
//     rejections into the contract's {"ok":false,"reason":<§7>} JSON (Gin has
//     no error-handler hook once a middleware has written the response, so
//     the harness buffers the write);
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
// chainless message tokens (stamped by ginsig itself). It prints
// "ready <addr>" once listening and exits cleanly on SIGTERM.
package main

import (
	"bytes"
	"context"
	"encoding/json"
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

	"github.com/gin-gonic/gin"

	"valiss.dev/valiss"
	"valiss.dev/valiss/contrib/ginauth"
	"valiss.dev/valiss/contrib/ginsig"
	"valiss.dev/valiss/contrib/httpauth"

	"github.com/valiss-dev/interop/harness/go-0.13-gin1/internal/reason"
	"github.com/valiss-dev/interop/harness/go-0.13-gin1/internal/wire"
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

	gin.SetMode(gin.ReleaseMode)
	engine := gin.New()
	engine.Use(contractResponses)

	switch *mode {
	case "signed":
		// The fixture tokens carry no HTTP extension claim, and the interop
		// contract has no extension dimension, so the fail-closed default
		// (deny extensionless tokens) is relaxed with the adapter's own
		// option.
		verifier := valiss.NewVerifier(operatorPub, allow,
			valiss.WithReplayCache(valiss.NewMemoryReplayCache()))
		engine.Use(ginauth.NewMiddleware(verifier, httpauth.AllowMissingExtension()))
		engine.POST(wire.InvokePath, acceptSigned)
	case "message":
		// No httpsig.WithChainCache: a cache would let a bare token reuse a
		// chain negotiated by an earlier request, and the suite's
		// bare-signals-negotiation scenario asserts the no_chain rejection.
		engine.Use(sinkAudience)
		engine.Use(ginsig.NewMiddleware(operatorPub))
		engine.POST(wire.InvokePath, acceptMessage(allow))
	default:
		log.Fatalf("unknown mode %q", *mode)
	}

	lis, err := net.Listen("tcp", *addr)
	if err != nil {
		log.Fatalf("listen %s: %v", *addr, err)
	}

	sigs := make(chan os.Signal, 1)
	signal.Notify(sigs, syscall.SIGTERM, syscall.SIGINT)

	httpSrv := &http.Server{Handler: engine}
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

// acceptSigned renders the contract accept for a request ginauth
// authenticated; the middleware aborted every other request before it got
// here.
func acceptSigned(c *gin.Context) {
	id, ok := ginauth.IdentityFrom(c)
	if !ok {
		c.JSON(http.StatusUnauthorized, wire.Reject{Reason: "missing"})
		return
	}
	var user *string
	if id.User != nil {
		user = &id.User.Name
	}
	c.JSON(http.StatusOK, wire.Accept{OK: true, Tenant: id.Account.Name, User: user})
}

// acceptMessage renders the contract accept for a message ginsig verified,
// after holding the chain's account to the same allowlist signed mode
// enforces. The library places revocation with the receiver (message
// verification itself is offline), so this check is the documented
// integration point, not a bypass of adapter code.
func acceptMessage(allow valiss.Allowlist) gin.HandlerFunc {
	return func(c *gin.Context) {
		claims, ok := ginsig.MessageFrom(c)
		if !ok {
			c.JSON(http.StatusUnauthorized, wire.Reject{Reason: "missing"})
			return
		}
		if !allow.Allowed(claims.Account.ID) {
			c.JSON(http.StatusUnauthorized, wire.Reject{Reason: "not_allowlisted"})
			return
		}
		c.JSON(http.StatusOK, wire.Accept{OK: true, Tenant: claims.Account.Name, User: &claims.User.Name})
	}
}

// sinkAudience makes the shipped receiver expect the interop suite's
// logical audience. httpsig.Audience derives the expected audience from the
// request's Host and URL path, and the receiver appends that binding after
// every caller option, so no ginsig/httpsig option can pin the
// scenarios.yaml audience "interop://sink". Rewriting the audience-bearing
// fields is safe here: Gin routed on the original path before middlewares
// run, and nothing downstream reads Host or the path.
func sinkAudience(c *gin.Context) {
	c.Request.Host = wire.SinkAudience
	c.Request.URL.Path = ""
}

// contractResponses buffers each response and rewrites adapter rejections
// into the contract's reject JSON. ginauth and ginsig write rejections as
// plain text (the error string, or ginsig's fixed chain-required line) and
// abort; the write has already happened by the time control returns, so the
// only Gin-native interception point is the response writer itself. JSON
// responses (the handlers' own accept and reject shapes) pass through
// untouched, as do headers, including the valiss-chain: required signal
// ginsig stamps before writing.
func contractResponses(c *gin.Context) {
	cw := &captureWriter{ResponseWriter: c.Writer}
	c.Writer = cw
	c.Next()

	status := cw.status
	if status == 0 {
		status = http.StatusOK
	}
	body := cw.body.Bytes()
	if status != http.StatusOK && !strings.HasPrefix(cw.Header().Get("Content-Type"), "application/json") {
		rendered, err := json.Marshal(wire.Reject{Reason: reason.Code(string(body))})
		if err != nil {
			log.Printf("encode reject: %v", err)
			rendered = []byte(`{"ok":false,"reason":"malformed"}`)
		}
		cw.Header().Set("Content-Type", "application/json")
		body = append(rendered, '\n')
	}
	cw.ResponseWriter.WriteHeader(status)
	if _, err := cw.ResponseWriter.Write(body); err != nil {
		log.Printf("write response: %v", err)
	}
}

// captureWriter is a gin.ResponseWriter that holds the status and body back
// so contractResponses can reshape rejections after the handler chain ran.
type captureWriter struct {
	gin.ResponseWriter
	status int
	body   bytes.Buffer
}

func (w *captureWriter) WriteHeader(code int) { w.status = code }

// WriteHeaderNow suppresses Gin's eager header flush; contractResponses
// writes the response once the chain has finished.
func (w *captureWriter) WriteHeaderNow() {}

func (w *captureWriter) Write(b []byte) (int, error) { return w.body.Write(b) }

func (w *captureWriter) WriteString(s string) (int, error) { return w.body.WriteString(s) }

func (w *captureWriter) Status() int {
	if w.status != 0 {
		return w.status
	}
	return w.ResponseWriter.Status()
}

func (w *captureWriter) Size() int { return w.body.Len() }

func (w *captureWriter) Written() bool { return w.status != 0 || w.body.Len() > 0 }
