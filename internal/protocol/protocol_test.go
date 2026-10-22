package protocol

import (
	"bytes"
	"strings"
	"testing"
)

// TestLZ4DecompressRejectsOutputBomb is the regression test for the OOM hole:
// a tiny token that declares an enormous match length used to make the loop
// append until the process ran out of memory. Each 0xff byte in the extension
// chain adds 255 to matchLen, so a few tens of KB of input can claim gigabytes
// of output.
func TestLZ4DecompressRejectsOutputBomb(t *testing.T) {
	// token 0x1f: one literal byte, then a match whose length extension runs
	// through the 0xff chain below.
	payload := []byte{0x1f, 'A', 0x01, 0x00}
	// 40000 * 255 ~= 10.2 MB of claimed output, past the 8 MB cap.
	payload = append(payload, bytes.Repeat([]byte{255}, 40000)...)
	payload = append(payload, 0)

	if _, err := lz4Decompress(payload); err == nil {
		t.Fatalf("expected oversized lz4 output to be rejected")
	}
}

// TestLZ4DecompressAllowsReasonableOutput confirms the cap does not reject
// legitimate payloads that expand by a large but bounded factor.
func TestLZ4DecompressAllowsReasonableOutput(t *testing.T) {
	// A 64 KB match is well within the cap and must decode fine.
	in := bytes.Repeat([]byte{'z'}, 64<<10)
	got, err := lz4Decompress(lz4AllLiteral(in))
	if err != nil {
		t.Fatalf("decompress error = %v", err)
	}
	if !bytes.Equal(got, in) {
		t.Fatalf("mismatch: got %d bytes want %d", len(got), len(in))
	}
}

// TestLZ4RoundTrip checks that the all-literal encoder still decodes.
func TestLZ4RoundTrip(t *testing.T) {
	for _, size := range []int{0, 1, 14, 15, 16, 300, 70000} {
		in := bytes.Repeat([]byte("abcdefghij"), size/10+1)[:size]
		enc := lz4AllLiteral(in)
		got, err := lz4Decompress(enc)
		if err != nil {
			t.Fatalf("size %d: decompress error = %v", size, err)
		}
		if !bytes.Equal(got, in) {
			t.Fatalf("size %d: round trip mismatch (got %d bytes)", size, len(got))
		}
	}
}

// TestLZ4DecompressRejectsTruncated makes sure malformed input errors instead of
// panicking on slice bounds. An empty input is not malformed: it is a valid
// empty stream and must decode to zero bytes.
func TestLZ4DecompressRejectsTruncated(t *testing.T) {
	if got, err := lz4Decompress(nil); err != nil || len(got) != 0 {
		t.Fatalf("empty input should decode to empty, got %q err=%v", got, err)
	}
	cases := [][]byte{
		{0xf0},                  // literal length extension with nothing after it
		{0xf1, 'a'},             // literal run shorter than declared
		{0x1f, 'a', 0x01},       // match offset truncated
		{0x10, 'a', 0x05, 0x00}, // offset points before the output start
	}
	for i, in := range cases {
		if _, err := lz4Decompress(in); err == nil {
			t.Fatalf("case %d: expected error for %x", i, in)
		}
	}
}

// TestParseRecordsStopsOnUnknownVersion documents that a corrupt stream yields
// no records and zero consumed bytes, which is what nextRecord relies on to
// detect a stuck stream instead of looping forever.
func TestParseRecordsStopsOnUnknownVersion(t *testing.T) {
	bad := []byte{ctHandshake, 0xff, 0xff, 0x00, 0x01, 'x'}
	recs, consumed := parseRecords(bad)
	if len(recs) != 0 {
		t.Fatalf("expected no records, got %d", len(recs))
	}
	if consumed != 0 {
		t.Fatalf("expected consumed=0, got %d", consumed)
	}
}

// TestParseRecordsFramesPartial checks a complete record followed by a partial
// header: the first is returned, the leftover is retained.
func TestParseRecordsFramesPartial(t *testing.T) {
	full, err := buildRecord(ctHandshake, []byte("hello"))
	if err != nil {
		t.Fatalf("buildRecord: %v", err)
	}
	buf := append(append([]byte(nil), full...), 0x16, 0xf1)
	recs, consumed := parseRecords(buf)
	if len(recs) != 1 {
		t.Fatalf("expected 1 record, got %d", len(recs))
	}
	if string(recs[0].Payload) != "hello" {
		t.Fatalf("payload = %q", recs[0].Payload)
	}
	if consumed != len(full) {
		t.Fatalf("consumed = %d, want %d", consumed, len(full))
	}
}

// TestBuildRecordRejectsOversize guards the 16 bit length field.
func TestBuildRecordRejectsOversize(t *testing.T) {
	if _, err := buildRecord(ctAppData, make([]byte, 0x10000)); err == nil {
		t.Fatalf("expected oversize record to be rejected")
	}
	if _, err := buildRecord(ctAppData, make([]byte, 0xffff)); err != nil {
		t.Fatalf("max size record should be accepted: %v", err)
	}
}

// TestParseShortlinkRejectsTruncated covers the length prefix check.
func TestParseShortlinkRejectsTruncated(t *testing.T) {
	pkt := buildShortlink(transferCmd, 0, []byte("body"), defaultVer)
	if _, err := parseShortlink(pkt[:10]); err == nil {
		t.Fatalf("expected short packet to be rejected")
	}
	// Total length claiming more than we hold must also be rejected.
	over := append([]byte(nil), pkt...)
	over[0], over[1] = 0xff, 0xff
	if _, err := parseShortlink(over); err == nil {
		t.Fatalf("expected overlong total length to be rejected")
	}
	got, err := parseShortlink(pkt)
	if err != nil {
		t.Fatalf("parseShortlink: %v", err)
	}
	if string(got.Body) != "body" || got.Cmd != transferCmd {
		t.Fatalf("parsed packet = %+v", got)
	}
}

// TestPBVarintRoundTrip covers the protobuf writer and reader used to build
// upstream requests.
func TestPBVarintRoundTrip(t *testing.T) {
	vals := []uint64{0, 1, 127, 128, 300, 16384, 1 << 32, 1<<63 - 1}
	for _, v := range vals {
		enc := varint(v)
		got, n, err := readVarint(enc, 0)
		if err != nil {
			t.Fatalf("varint(%d): %v", v, err)
		}
		if got != v || n != len(enc) {
			t.Fatalf("varint(%d) decoded as %d (consumed %d of %d)", v, got, n, len(enc))
		}
	}
}

// TestReadVarintRejectsOverflow ensures a hostile 11 byte varint errors.
func TestReadVarintRejectsOverflow(t *testing.T) {
	if _, _, err := readVarint(bytes.Repeat([]byte{0x80}, 16), 0); err == nil {
		t.Fatalf("expected overflow error")
	}
}

// TestSplitHTTPBodyRequiresTerminator verifies we reject non-HTTP replies
// rather than treating the whole buffer as a body.
func TestSplitHTTPBodyRequiresTerminator(t *testing.T) {
	if _, ok := splitHTTPBody([]byte("not http at all")); ok {
		t.Fatalf("expected missing terminator to be reported")
	}
	body, ok := splitHTTPBody([]byte("HTTP/1.0 200 OK\r\n\r\npayload"))
	if !ok || string(body) != "payload" {
		t.Fatalf("body = %q ok = %v", body, ok)
	}
}

// TestSessionBlobRoundTrip covers the session serialisation used to persist
// credentials between restarts.
func TestSessionBlobRoundTrip(t *testing.T) {
	st := WmpfSession{
		Session: AppSession{
			SendKey:   []byte{1, 2, 3},
			RecvKey:   []byte{4, 5, 6},
			F9:        []byte{7},
			UIN:       998877,
			Ticket:    []byte{8, 9},
			DeviceID:  []byte("dev"),
			HostAppID: []byte("wxapp"),
		},
		PSK: pskEntry{
			PSKType: 1, PreSharedKey: "abcd", TicketEntry: "ef01",
			Lifetime: 3600, ExpiredAt: 9999999999,
		},
		ShortlinkTargets: []Target{{IP: "1.2.3.4", Port: 80}},
		TCPProxy:         "",
	}
	back, err := sessionFromBlob(st.toBlob())
	if err != nil {
		t.Fatalf("sessionFromBlob: %v", err)
	}
	if back.Session.UIN != st.Session.UIN {
		t.Fatalf("uin = %d", back.Session.UIN)
	}
	if !bytes.Equal(back.Session.SendKey, st.Session.SendKey) {
		t.Fatalf("send key mismatch")
	}
	if back.PSK.PreSharedKey != st.PSK.PreSharedKey {
		t.Fatalf("psk mismatch")
	}
	if len(back.ShortlinkTargets) != 1 || back.ShortlinkTargets[0].IP != "1.2.3.4" {
		t.Fatalf("targets = %+v", back.ShortlinkTargets)
	}
}

// TestSessionFromBlobRejectsIncomplete ensures a corrupt row surfaces as an
// error instead of a zero-valued session that would fail later and confusingly.
func TestSessionFromBlobRejectsIncomplete(t *testing.T) {
	if _, err := sessionFromBlob(map[string]any{}); err == nil {
		t.Fatalf("expected error for empty blob")
	}
	if _, err := sessionFromBlob(map[string]any{
		"session":   map[string]any{"uin": 1},
		"psk_entry": map[string]any{},
	}); err == nil || !strings.Contains(err.Error(), "incomplete") {
		t.Fatalf("expected incomplete error, got %v", err)
	}
}
