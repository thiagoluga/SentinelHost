package web

import (
	"net/http"
	"time"
)

// handleRestart stops the panel so the next visit starts the binary now on disk.
//
// An update replaces the FILE. The process already running is the old program — it has the
// old code in memory and keeps serving it, which is why the install says so. Telling the
// user that and then leaving them to work out what to do about it is half an answer, and on
// shared hosting with no shell it is no answer at all: there is nothing they can type.
//
// Stopping is the whole restart. The PHP bridge starts the panel whenever it is not
// answering, so the next visit brings up the new one — that is the shape the bridge was
// built for, and the reason its own comment says the panel dying "is just something the
// next visit fixes".
//
// Where there is no bridge — a workstation, an SSH tunnel — this stops the panel and does
// not bring it back, so the response says which of the two happened rather than promising a
// restart it cannot guarantee.
func (s *Server) handleRestart(w http.ResponseWriter, req *http.Request) {
	if s.stop == nil {
		writeErr(w, http.StatusNotImplemented,
			"this panel was not started in a way that lets it stop itself")
		return
	}

	s.logAction(req, "the panel was asked to restart, to run the binary on disk", nil)

	// Answer BEFORE stopping. The browser needs this response to know the request
	// succeeded; shutting down first would drop the connection and the user would see a
	// network error for an action that worked.
	writeJSON(w, http.StatusOK, map[string]any{
		"stopping": true,
		"note": "the panel is stopping. If it is installed behind the PHP bridge, the next " +
			"visit starts the new binary — reload in a few seconds. If you started it " +
			"yourself, start it again the same way.",
	})
	if f, ok := w.(http.Flusher); ok {
		f.Flush()
	}

	// A moment for the response to reach the client, then stop. Not in the request
	// goroutine's path: shutdown waits for in-flight requests, and this IS one.
	go func() {
		time.Sleep(500 * time.Millisecond)
		s.stop()
	}()
}
