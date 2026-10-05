package api

import (
	"context"
	"fmt"
	"net"
	"net/http"
	"testing"
	"time"
)

func TestServerCancelsStreamsBeforeDrain(t *testing.T) {
	listener, e := net.Listen("tcp4", "127.0.0.1:0")
	if e != nil {
		t.Fatal(e)
	}
	port := listener.Addr().(*net.TCPAddr).Port
	listener.Close()
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	ready := make(chan struct{})
	done := make(chan error, 1)
	handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/event-stream")
		w.Write([]byte(": ready\n\n"))
		w.(http.Flusher).Flush()
		close(ready)
		<-r.Context().Done()
	})
	go func() { done <- Serve(ctx, "127.0.0.1", "::1", port, handler) }()
	var response *http.Response
	for deadline := time.Now().Add(3 * time.Second); time.Now().Before(deadline); {
		response, e = http.Get("http://" + net.JoinHostPort("127.0.0.1", fmt.Sprint(port)))
		if e == nil {
			break
		}
		time.Sleep(10 * time.Millisecond)
	}
	if e != nil {
		t.Fatal(e)
	}
	defer response.Body.Close()
	<-ready
	cancel()
	select {
	case e := <-done:
		if e != nil {
			t.Fatal(e)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("shutdown waited on an open stream")
	}
}
