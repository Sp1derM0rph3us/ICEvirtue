package api

import (
	"context"
	"errors"
	"fmt"
	"log"
	"net"
	"net/http"
	"strconv"
	"time"
)

// Serve binds before reporting readiness and closes all listeners on every exit path.
func Serve(ctx context.Context, ipv4, ipv6 string, port int, handler http.Handler) error {
	ctx, stop := context.WithCancel(ctx)
	defer stop()
	var listeners []net.Listener
	for _, b := range []struct{ network, host string }{{"tcp4", ipv4}, {"tcp6", ipv6}} {
		ln, e := net.Listen(b.network, net.JoinHostPort(b.host, strconv.Itoa(port)))
		if e != nil {
			log.Printf("listen %s: %v", b.host, e)
			continue
		}
		listeners = append(listeners, ln)
	}
	if len(listeners) == 0 {
		return fmt.Errorf("no dashboard listen address could be bound")
	}
	for _, ln := range listeners {
		defer ln.Close()
	}
	srv := &http.Server{Handler: handler, ReadHeaderTimeout: 10 * time.Second, IdleTimeout: 120 * time.Second, BaseContext: func(net.Listener) context.Context { return ctx }}
	defer srv.Close()
	errs := make(chan error, len(listeners))
	for _, ln := range listeners {
		log.Printf("dashboard listening on %s", ln.Addr())
		go func(l net.Listener) { errs <- srv.Serve(l) }(ln)
	}
	var result error
	select {
	case <-ctx.Done():
	case result = <-errs:
	}
	stop() // Close streaming requests before draining the HTTP server.
	shutdown, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	if e := srv.Shutdown(shutdown); e != nil {
		result = errors.Join(result, e)
	}
	if errors.Is(result, http.ErrServerClosed) {
		return nil
	}
	return result
}
