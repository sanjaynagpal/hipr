// Package inspect defines the records hipr produces for each proxied
// exchange and the sinks that consume them.
package inspect

import (
	"bytes"
	"compress/gzip"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"sync"
	"time"
	"unicode/utf8"
)

// Event describes one proxied HTTP exchange or one opaque CONNECT tunnel.
type Event struct {
	ID         uint64        `json:"id"`
	Time       time.Time     `json:"time"`
	Duration   time.Duration `json:"duration_ns"`
	Kind       string        `json:"kind"` // "http" or "tunnel"
	ClientAddr string        `json:"client_addr"`
	Method     string        `json:"method"`
	URL        string        `json:"url"`
	Proto      string        `json:"proto,omitempty"`
	ReqHeader  http.Header   `json:"req_header,omitempty"`
	ReqBody    Body          `json:"req_body"`
	Status     int           `json:"status,omitempty"`
	RespHeader http.Header   `json:"resp_header,omitempty"`
	RespBody   Body          `json:"resp_body"`
	BytesUp    int64         `json:"bytes_up,omitempty"`   // tunnels only
	BytesDown  int64         `json:"bytes_down,omitempty"` // tunnels only
	Error      string        `json:"error,omitempty"`
}

// Body is a captured message body. Data holds at most the configured limit
// and is gzip-decoded when possible; Size is the number of bytes seen on the wire.
type Body struct {
	Data      []byte
	Size      int64
	Truncated bool
}

func (b Body) MarshalJSON() ([]byte, error) {
	v := struct {
		Size      int64  `json:"size"`
		Truncated bool   `json:"truncated,omitempty"`
		Text      string `json:"text,omitempty"`
		Base64    string `json:"base64,omitempty"`
	}{Size: b.Size, Truncated: b.Truncated}
	if utf8.Valid(b.Data) {
		v.Text = string(b.Data)
	} else {
		v.Base64 = base64.StdEncoding.EncodeToString(b.Data)
	}
	return json.Marshal(v)
}

// Decode undoes a Content-Encoding where hipr knows how. It is best effort:
// a truncated gzip stream yields whatever decoded before the cut.
func Decode(data []byte, encoding string) []byte {
	if encoding != "gzip" || len(data) == 0 {
		return data
	}
	zr, err := gzip.NewReader(bytes.NewReader(data))
	if err != nil {
		return data
	}
	out, _ := io.ReadAll(zr)
	if len(out) == 0 {
		return data
	}
	return out
}

// Sink receives finished events. Implementations must be safe for concurrent use.
type Sink interface {
	Record(*Event)
}

// Multi fans an event out to several sinks.
type Multi []Sink

func (m Multi) Record(e *Event) {
	for _, s := range m {
		s.Record(e)
	}
}

// Text writes a human-readable summary, with headers and bodies when Verbose.
type Text struct {
	mu      sync.Mutex
	W       io.Writer
	Verbose bool
}

func (t *Text) Record(e *Event) {
	t.mu.Lock()
	defer t.mu.Unlock()
	d := e.Duration.Round(time.Millisecond)
	switch {
	case e.Kind == "tunnel":
		fmt.Fprintf(t.W, "#%d %s %s tunnel up=%dB down=%dB (%s)", e.ID, e.Method, e.URL, e.BytesUp, e.BytesDown, d)
	case e.Status == 0:
		fmt.Fprintf(t.W, "#%d %s %s -> ERROR (%s)", e.ID, e.Method, e.URL, d)
	default:
		fmt.Fprintf(t.W, "#%d %s %s -> %d %dB (%s)", e.ID, e.Method, e.URL, e.Status, e.RespBody.Size, d)
	}
	if e.Error != "" {
		fmt.Fprintf(t.W, " error: %s", e.Error)
	}
	fmt.Fprintln(t.W)
	if !t.Verbose || e.Kind == "tunnel" {
		return
	}
	t.section("> ", e.ReqHeader, e.ReqBody)
	t.section("< ", e.RespHeader, e.RespBody)
}

func (t *Text) section(prefix string, h http.Header, b Body) {
	for k, vs := range h {
		for _, v := range vs {
			fmt.Fprintf(t.W, "  %s%s: %s\n", prefix, k, v)
		}
	}
	if len(b.Data) == 0 {
		return
	}
	if !utf8.Valid(b.Data) {
		fmt.Fprintf(t.W, "  %s<binary body, %d bytes>\n", prefix, b.Size)
		return
	}
	fmt.Fprintf(t.W, "  %s\n  %s%s\n", prefix, prefix, bytes.ReplaceAll(b.Data, []byte("\n"), []byte("\n  "+prefix)))
	if b.Truncated {
		fmt.Fprintf(t.W, "  %s<truncated, %d bytes total>\n", prefix, b.Size)
	}
}

// JSONL writes one JSON object per event.
type JSONL struct {
	mu  sync.Mutex
	enc *json.Encoder
}

func NewJSONL(w io.Writer) *JSONL { return &JSONL{enc: json.NewEncoder(w)} }

func (j *JSONL) Record(e *Event) {
	j.mu.Lock()
	defer j.mu.Unlock()
	_ = j.enc.Encode(e)
}
