package engine

import (
	"io"
	"log"
	"os"

	"github.com/Sp1derM0rph3us/ICEvirtue/internal/serverlogs"
)

// scanLog carries the reconnaissance engine's activity to the terminal and to
// the dedicated scan-log buffer that the admin "Server logs" page reads.
//
// Keeping the engine on its own logger is what lets that page show scan logs
// only — pipeline starts and completions, per-stage summaries, per-tool success
// and failure, halts and totals — while HTTP request logging, authentication,
// account changes and template errors stay on the standard logger (stderr plus
// serverlogs.Default) and out of this view. Both destinations still receive the
// engine's lines, so the terminal is unchanged; only the admin page is narrowed.
//
// Flags match the standard logger's defaults so a line reads identically in the
// terminal whichever logger emitted it.
var scanLog = log.New(io.MultiWriter(os.Stderr, serverlogs.Scans), "", log.LstdFlags)

// logf records one scan log line. It is the engine's drop-in replacement for
// log.Printf: every log call in this package goes through it so that all scan
// output, and nothing else, reaches the scan-log buffer.
func logf(format string, args ...any) {
	scanLog.Printf(format, args...)
}
