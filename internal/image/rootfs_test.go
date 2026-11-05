package image

import (
	"archive/tar"
	"bytes"
	"os"
	"path/filepath"
	"syscall"
	"testing"
)

func layer(t *testing.T, hs ...*tar.Header) *bytes.Buffer {
	t.Helper()
	var buf bytes.Buffer
	tw := tar.NewWriter(&buf)
	for _, h := range hs {
		if h.Typeflag == tar.TypeReg {
			h.Size = 2
		}
		if err := tw.WriteHeader(h); err != nil {
			t.Fatal(err)
		}
		if h.Typeflag == tar.TypeReg {
			tw.Write([]byte("hi"))
		}
	}
	tw.Close()
	return &buf
}

func TestExtractRecordsFixups(t *testing.T) {
	dir := t.TempDir()
	fixups, _, err := extract(layer(t,
		&tar.Header{Name: "etc/", Typeflag: tar.TypeDir, Mode: 0o755},
		&tar.Header{Name: "etc/plain", Typeflag: tar.TypeReg, Mode: 0o644},
		&tar.Header{Name: "etc/shadow", Typeflag: tar.TypeReg, Mode: 0o640, Gid: 42},
		&tar.Header{Name: "usr/bin/su", Typeflag: tar.TypeReg, Mode: 0o4755},
		&tar.Header{Name: "home/node/", Typeflag: tar.TypeDir, Mode: 0o700, Uid: 1000, Gid: 1000},
		&tar.Header{Name: "bin", Typeflag: tar.TypeSymlink, Linkname: "usr/bin"},
		&tar.Header{Name: "usr/bin/su2", Typeflag: tar.TypeLink, Linkname: "usr/bin/su"},
		&tar.Header{Name: ".ember/agent", Typeflag: tar.TypeReg, Mode: 0o755},
	), dir)
	if err != nil {
		t.Fatal(err)
	}
	got := map[string]fixup{}
	for _, f := range fixups {
		got[f.path] = f
	}
	if _, ok := got["/etc/plain"]; ok {
		t.Error("plain root-owned file should need no fixup")
	}
	if f := got["/etc/shadow"]; f.gid != 42 || f.mode != syscall.S_IFREG|0o640 {
		t.Errorf("shadow fixup %+v", f)
	}
	if f := got["/usr/bin/su"]; f.mode != syscall.S_IFREG|0o4755 {
		t.Errorf("setuid fixup %+v", f)
	}
	if f := got["/home/node"]; f.uid != 1000 || f.mode != syscall.S_IFDIR|0o700 {
		t.Errorf("home fixup %+v", f)
	}
	if _, err := os.Stat(filepath.Join(dir, ".ember")); err == nil {
		t.Error("image content must not provide /.ember")
	}
	a, _ := os.Stat(filepath.Join(dir, "usr/bin/su"))
	b, _ := os.Stat(filepath.Join(dir, "usr/bin/su2"))
	if !os.SameFile(a, b) {
		t.Error("hardlink not preserved")
	}
}

func TestExtractCannotEscapeThroughSymlink(t *testing.T) {
	outside := t.TempDir()
	dir := t.TempDir()
	_, _, err := extract(layer(t,
		&tar.Header{Name: "evil", Typeflag: tar.TypeSymlink, Linkname: outside},
		&tar.Header{Name: "evil/pwned", Typeflag: tar.TypeReg, Mode: 0o644},
	), dir)
	if err == nil {
		t.Error("expected an error writing through an escaping symlink")
	}
	if _, serr := os.Stat(filepath.Join(outside, "pwned")); serr == nil {
		t.Fatal("extraction wrote outside the root")
	}
}
