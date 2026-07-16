// Command server is the go-0.13 interop harness server (CONTRACT.md): it
// exposes exactly one protected operation over HTTP or gRPC.
//
// In signed mode it runs the valiss Verifier against the pinned operator key
// and the file-backed allowlist, with a replay cache (signed requests must
// carry a nonce) and bearer user tokens accepted. In message mode it
// verifies a per-message proof of origin: audience pinned to the interop
// sink, checksum bound to the received payload, and the chain's account
// checked against the same allowlist. The chain arrives embedded in the
// token or detached in the valiss-chain-* request headers; a token with no
// chain anywhere is rejected no_chain and the response carries the
// chain-negotiation signal (valiss-chain: required — response header on
// HTTP, trailer on gRPC), inviting a retransmit with the detached headers.
//
// Accept answers HTTP 200 / gRPC OK with the contract's accept JSON; reject
// answers HTTP 401 / gRPC UNAUTHENTICATED with {"ok":false,"reason":<§7>}.
// It prints "ready <addr>" once listening and exits cleanly on SIGTERM.
package main

import (
	"context"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"log"
	"net"
	"net/http"
	"os"
	"os/signal"
	"strings"
	"syscall"

	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/metadata"
	"google.golang.org/grpc/status"

	"valiss.dev/valiss"

	"github.com/valiss-dev/interop/harness/go-0.13/internal/reason"
	"github.com/valiss-dev/interop/harness/go-0.13/internal/wire"
	"github.com/valiss-dev/interop/harness/go-0.13/interoppb"
)

func main() {
	log.SetFlags(0)
	log.SetPrefix("server: ")

	var (
		transport = flag.String("transport", "http", "transport to serve: http or grpc")
		addr      = flag.String("addr", "127.0.0.1:0", "HOST:PORT to listen on")
		operator  = flag.String("operator", "", "file with the pinned operator public key")
		allowlist = flag.String("allowlist", "", "file with the accepted account-token ids, one per line")
		mode      = flag.String("mode", "signed", "verification mode: signed or message")
	)
	flag.Parse()

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

	s := &server{
		mode:        *mode,
		operatorPub: operatorPub,
		allowlist:   allow,
		verifier: valiss.NewVerifier(operatorPub, allow,
			valiss.WithReplayCache(valiss.NewMemoryReplayCache())),
	}
	if *mode != "signed" && *mode != "message" {
		log.Fatalf("unknown mode %q", *mode)
	}

	lis, err := net.Listen("tcp", *addr)
	if err != nil {
		log.Fatalf("listen %s: %v", *addr, err)
	}

	sigs := make(chan os.Signal, 1)
	signal.Notify(sigs, syscall.SIGTERM, syscall.SIGINT)

	switch *transport {
	case "http":
		mux := http.NewServeMux()
		mux.HandleFunc(wire.InvokePath, s.handleHTTP)
		httpSrv := &http.Server{Handler: mux}
		go func() {
			if err := httpSrv.Serve(lis); err != nil && !errors.Is(err, http.ErrServerClosed) {
				log.Fatalf("serve: %v", err)
			}
		}()
		ready(lis)
		<-sigs
		if err := httpSrv.Shutdown(context.Background()); err != nil {
			log.Fatalf("shutdown: %v", err)
		}
	case "grpc":
		grpcSrv := grpc.NewServer()
		interoppb.RegisterInteropServer(grpcSrv, s)
		go func() {
			if err := grpcSrv.Serve(lis); err != nil {
				log.Fatalf("serve: %v", err)
			}
		}()
		ready(lis)
		<-sigs
		grpcSrv.GracefulStop()
	default:
		log.Fatalf("unknown transport %q", *transport)
	}
}

// ready prints the contract's readiness line with the bound address.
func ready(lis net.Listener) {
	fmt.Printf("ready %s\n", lis.Addr())
}

// server carries the verification state shared by both transports.
type server struct {
	interoppb.UnimplementedInteropServer
	mode        string
	operatorPub string
	allowlist   valiss.Allowlist
	verifier    *valiss.Verifier
}

// verifySigned runs the request-credential verification and renders the
// contract outcome: the accept shape, or the reject shape with the §7 code.
func (s *server) verifySigned(req valiss.Request) (accepted *wire.Accept, rejected *wire.Reject) {
	id, err := s.verifier.VerifyRequest(req)
	if err != nil {
		return nil, &wire.Reject{Reason: reason.Code(err)}
	}
	var user *string
	if id.User != nil {
		user = &id.User.Name
	}
	return &wire.Accept{OK: true, Tenant: id.Account.Name, User: user}, nil
}

// verifyMessage verifies a per-message proof over the payload as received,
// with the audience pinned to the interop sink and the chain's account held
// to the same allowlist the signed mode enforces. When the token embeds no
// chain the detached valiss-chain-* request headers supply it. chainRequired
// reports the one failure a retransmit with the chain can cure
// (valiss.ErrNoChain): the transport then attaches the negotiation signal.
func (s *server) verifyMessage(token, chainAccountToken, chainUserToken string, payload []byte) (accepted *wire.Accept, rejected *wire.Reject, chainRequired bool) {
	if token == "" {
		return nil, &wire.Reject{Reason: "missing"}, false
	}
	opts := []valiss.VerifyMessageOption{
		valiss.ExpectAudience(wire.SinkAudience),
		valiss.WithPayload(payload),
	}
	if chainAccountToken != "" || chainUserToken != "" {
		opts = append(opts, valiss.WithChainTokens(chainAccountToken, chainUserToken))
	}
	claims, err := valiss.VerifyMessage(token, s.operatorPub, opts...)
	if err != nil {
		return nil, &wire.Reject{Reason: reason.Code(err)}, errors.Is(err, valiss.ErrNoChain)
	}
	if !s.allowlist.Allowed(claims.Account.ID) {
		return nil, &wire.Reject{Reason: "not_allowlisted"}, false
	}
	return &wire.Accept{OK: true, Tenant: claims.Account.Name, User: &claims.User.Name}, nil, false
}

// handleHTTP is the protected operation over HTTP.
func (s *server) handleHTTP(w http.ResponseWriter, r *http.Request) {
	var accepted *wire.Accept
	var rejected *wire.Reject
	var chainRequired bool
	switch s.mode {
	case "signed":
		nonce := r.Header.Get(valiss.HeaderNonce)
		accepted, rejected = s.verifySigned(valiss.Request{
			AccountToken: r.Header.Get(valiss.HeaderAccountToken),
			UserToken:    r.Header.Get(valiss.HeaderUserToken),
			Timestamp:    r.Header.Get(valiss.HeaderTimestamp),
			Signature:    r.Header.Get(valiss.HeaderSignature),
			Context:      wire.HTTPRequestContext(r.Method, hostOf(r), r.URL.Path, nonce),
			Nonce:        nonce,
		})
	case "message":
		body, err := io.ReadAll(r.Body)
		if err != nil {
			http.Error(w, "reading request body", http.StatusBadRequest)
			return
		}
		accepted, rejected, chainRequired = s.verifyMessage(
			r.Header.Get(valiss.HeaderMessageToken),
			r.Header.Get(valiss.HeaderChainAccountToken),
			r.Header.Get(valiss.HeaderChainUserToken),
			body)
	}
	if rejected != nil {
		if chainRequired {
			w.Header().Set(valiss.HeaderChain, valiss.ChainRequired)
		}
		writeJSON(w, http.StatusUnauthorized, rejected)
		return
	}
	writeJSON(w, http.StatusOK, accepted)
}

// Invoke is the protected operation over gRPC. Rejections travel as an
// UNAUTHENTICATED status whose message is the contract's reject JSON; the
// chain-negotiation signal rides the trailing metadata.
func (s *server) Invoke(ctx context.Context, req *interoppb.InvokeRequest) (*interoppb.InvokeResponse, error) {
	md, _ := metadata.FromIncomingContext(ctx)
	var accepted *wire.Accept
	var rejected *wire.Reject
	var chainRequired bool
	switch s.mode {
	case "signed":
		nonce := first(md, valiss.HeaderNonce)
		accepted, rejected = s.verifySigned(valiss.Request{
			AccountToken: first(md, valiss.HeaderAccountToken),
			UserToken:    first(md, valiss.HeaderUserToken),
			Timestamp:    first(md, valiss.HeaderTimestamp),
			Signature:    first(md, valiss.HeaderSignature),
			Context:      wire.GRPCRequestContext(interoppb.Interop_Invoke_FullMethodName, nonce),
			Nonce:        nonce,
		})
	case "message":
		accepted, rejected, chainRequired = s.verifyMessage(
			first(md, valiss.HeaderMessageToken),
			first(md, valiss.HeaderChainAccountToken),
			first(md, valiss.HeaderChainUserToken),
			req.GetPayload())
	}
	if rejected != nil {
		if chainRequired {
			if err := grpc.SetTrailer(ctx, metadata.Pairs(valiss.HeaderChain, valiss.ChainRequired)); err != nil {
				return nil, status.Error(codes.Internal, "set chain trailer")
			}
		}
		raw, err := json.Marshal(rejected)
		if err != nil {
			return nil, status.Error(codes.Internal, "encode reject")
		}
		return nil, status.Error(codes.Unauthenticated, string(raw))
	}
	raw, err := json.Marshal(accepted)
	if err != nil {
		return nil, status.Error(codes.Internal, "encode accept")
	}
	return &interoppb.InvokeResponse{Json: string(raw)}, nil
}

// hostOf mirrors the reference transports' host derivation: the request Host
// with a fallback to the URL host (SPEC-1.md §5.3).
func hostOf(r *http.Request) string {
	if r.Host != "" {
		return r.Host
	}
	return r.URL.Host
}

func first(md metadata.MD, key string) string {
	if v := md.Get(key); len(v) > 0 {
		return v[0]
	}
	return ""
}

func writeJSON(w http.ResponseWriter, code int, v any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(code)
	if err := json.NewEncoder(w).Encode(v); err != nil {
		log.Printf("write response: %v", err)
	}
}
