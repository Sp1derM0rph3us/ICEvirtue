package engine

import (
	"strings"
	"testing"
	"time"

	"github.com/Sp1derM0rph3us/ICEvirtue/internal/models"
)

func TestWAFProcessTimeoutValidation(t *testing.T) {
	previous := GetWAFProcessTimeout()
	t.Cleanup(func() { _ = SetWAFProcessTimeout(previous) })
	if DefaultWAFProcessTimeout != 30*time.Second {
		t.Fatalf("default WAF process timeout = %s", DefaultWAFProcessTimeout)
	}
	if err := SetWAFProcessTimeout(200 * time.Millisecond); err != nil {
		t.Fatal(err)
	}
	if got := GetWAFProcessTimeout(); got != 200*time.Millisecond {
		t.Fatalf("active timeout = %s", got)
	}
	if err := SetWAFProcessTimeout(0); err == nil {
		t.Fatal("zero WAF timeout was accepted")
	}
	if got := GetWAFProcessTimeout(); got != 200*time.Millisecond {
		t.Fatalf("invalid update changed active timeout to %s", got)
	}
}

func TestWAFTimeoutKeepsOtherWorkersMoving(t *testing.T) {
	_, bin := newPipelineEnv(t, "passive")
	previous := GetWAFProcessTimeout()
	t.Cleanup(func() { _ = SetWAFProcessTimeout(previous) })
	if err := SetWAFProcessTimeout(200 * time.Millisecond); err != nil {
		t.Fatal(err)
	}
	fakeTool(t, bin, "wafw00f", `
case "$*" in
  *slow.example.com*) sleep 5;;
  *fast.example.com*) printf '%s\n' '[{"url":"https://fast.example.com","detected":false,"firewall":"None"}]';;
esac
`)
	start := time.Now()
	observations, err := RunWAFDetection([]models.AliveHost{
		{URL: "https://slow.example.com"},
		{URL: "https://fast.example.com"},
	})
	if err == nil || !strings.Contains(err.Error(), "1 of 2") {
		t.Fatalf("WAF timeout error = %v", err)
	}
	if len(observations) != 1 || observations[0].URL != "https://fast.example.com" || observations[0].Name != "none" {
		t.Fatalf("successful WAF observation lost: %+v", observations)
	}
	if elapsed := time.Since(start); elapsed >= 3*time.Second {
		t.Fatalf("timed-out WAF process blocked the batch for %s", elapsed)
	}
}
