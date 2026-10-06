package protocol

import (
	"bytes"
	"encoding/binary"
	"errors"
	"io"
	"strings"
	"testing"
)

func TestFrameRoundTrip(t *testing.T) {
	var buf bytes.Buffer
	frames := []struct {
		k    Kind
		body string
	}{
		{KindHello, `{"version":1,"username":"a"}`},
		{KindPing, ""},
		{KindMessage, strings.Repeat("x", MaxBody(KindMessage))},
	}
	for _, f := range frames {
		enc, err := EncodeFrame(f.k, []byte(f.body))
		if err != nil {
			t.Fatal(err)
		}
		buf.Write(enc)
	}
	for _, f := range frames {
		k, body, err := ReadFrame(&buf)
		if err != nil || k != f.k || string(body) != f.body {
			t.Fatalf("got kind=%d len=%d err=%v; want kind=%d len=%d", k, len(body), err, f.k, len(f.body))
		}
	}
	if _, _, err := ReadFrame(&buf); err != io.EOF {
		t.Fatalf("clean end of stream should be io.EOF, got %v", err)
	}
}

func TestOversizedFrameRejectedBeforeAllocation(t *testing.T) {
	// Header claims a 1 GiB message; the reader must refuse without reading it.
	hdr := make([]byte, headerLen)
	hdr[0] = byte(KindMessage)
	binary.BigEndian.PutUint32(hdr[1:], 1<<30)
	r := &countingReader{r: bytes.NewReader(hdr)}
	if _, _, err := ReadFrame(r); !errors.Is(err, ErrFrameSize) {
		t.Fatalf("got %v, want ErrFrameSize", err)
	}
	if r.n > headerLen {
		t.Fatalf("read %d bytes past the header", r.n-headerLen)
	}

	if _, err := EncodeFrame(KindMessage, make([]byte, MaxBody(KindMessage)+1)); !errors.Is(err, ErrFrameSize) {
		t.Fatalf("encode should enforce limits, got %v", err)
	}
}

type countingReader struct {
	r io.Reader
	n int
}

func (c *countingReader) Read(p []byte) (int, error) {
	n, err := c.r.Read(p)
	c.n += n
	return n, err
}

func TestUnknownKindAndTruncation(t *testing.T) {
	if _, _, err := ReadFrame(bytes.NewReader([]byte{99, 0, 0, 0, 0})); !errors.Is(err, ErrUnknownKind) {
		t.Fatalf("got %v, want ErrUnknownKind", err)
	}
	if _, err := EncodeFrame(Kind(99), nil); !errors.Is(err, ErrUnknownKind) {
		t.Fatalf("got %v", err)
	}
	enc, _ := EncodeFrame(KindAck, []byte(`{"message_id":"x"}`))
	if _, _, err := ReadFrame(bytes.NewReader(enc[:len(enc)-3])); !errors.Is(err, io.ErrUnexpectedEOF) {
		t.Fatalf("truncated body: got %v, want ErrUnexpectedEOF", err)
	}
	if _, _, err := ReadFrame(bytes.NewReader(enc[:2])); !errors.Is(err, io.ErrUnexpectedEOF) {
		t.Fatalf("truncated header: got %v, want ErrUnexpectedEOF", err)
	}
}

func TestChunkCodec(t *testing.T) {
	id := strings.Repeat("ab", 16)
	body, err := EncodeChunk(id, []byte("data"))
	if err != nil {
		t.Fatal(err)
	}
	gotID, data, err := DecodeChunk(body)
	if err != nil || gotID != id || string(data) != "data" {
		t.Fatalf("got %q %q %v", gotID, data, err)
	}
	for name, fn := range map[string]func() error{
		"short id":  func() error { _, err := EncodeChunk("abcd", []byte("x")); return err },
		"non-hex":   func() error { _, err := EncodeChunk(strings.Repeat("zz", 16), []byte("x")); return err },
		"empty":     func() error { _, err := EncodeChunk(id, nil); return err },
		"too big":   func() error { _, err := EncodeChunk(id, make([]byte, MaxChunkSize+1)); return err },
		"no data":   func() error { _, _, err := DecodeChunk(make([]byte, idRawLen)); return err },
		"too short": func() error { _, _, err := DecodeChunk([]byte{1, 2}); return err },
	} {
		if !errors.Is(fn(), ErrBadChunk) {
			t.Errorf("%s: want ErrBadChunk", name)
		}
	}
}

func TestUnmarshalRejectsTrailingData(t *testing.T) {
	var a Ack
	if err := Unmarshal([]byte(`{"message_id":"1"}`), &a); err != nil || a.MessageID != "1" {
		t.Fatalf("valid payload: %v %+v", err, a)
	}
	if err := Unmarshal([]byte(`{"message_id":"1"} {"x":1}`), &a); err == nil {
		t.Fatal("trailing data accepted")
	}
	if err := Unmarshal([]byte(`not json`), &a); err == nil {
		t.Fatal("garbage accepted")
	}
}
