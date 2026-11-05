package image

import (
	"archive/tar"
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"os"
	"os/exec"
	"path"
	"path/filepath"
	"strings"
	"syscall"
)

// fixup records metadata the unprivileged extraction could not reproduce;
// debugfs writes it into the finished filesystem.
type fixup struct {
	path     string // absolute path inside the image
	uid, gid int
	mode     uint32 // full st_mode, type bits included
}

// extract unpacks a flattened image tar under dir without privileges.
//
// Files are written with owner-writable modes so the tree stays removable.
// mke2fs later runs in a user namespace where the current user is root, so
// every file it copies is owned by root; entries that need another owner or
// a mode the extraction relaxed are returned as fixups. Device nodes are
// skipped (the guest mounts devtmpfs), and so are extended attributes.
//
// Every write goes through os.Root, so a hostile image cannot use symlinks
// to write outside dir.
func extract(r io.Reader, dir string) (fixups []fixup, size int64, err error) {
	root, err := os.OpenRoot(dir)
	if err != nil {
		return nil, 0, err
	}
	defer root.Close()
	tr := tar.NewReader(r)
	for {
		hdr, err := tr.Next()
		if errors.Is(err, io.EOF) {
			return fixups, size, nil
		}
		if err != nil {
			return nil, 0, err
		}
		rel := strings.TrimPrefix(path.Clean("/"+hdr.Name), "/")
		if rel == "" || rel == ".ember" || strings.HasPrefix(rel, ".ember/") {
			// The root directory's owner is set by mke2fs; .ember is ours.
			continue
		}
		target := filepath.FromSlash(rel)
		perm := uint32(hdr.Mode) & 0o7777
		var ftype uint32
		var written uint32 // the mode actually on disk

		switch hdr.Typeflag {
		case tar.TypeDir:
			ftype = syscall.S_IFDIR
			written = 0o755
			if err := root.MkdirAll(target, 0o755); err != nil {
				return nil, 0, err
			}
		case tar.TypeReg:
			ftype = syscall.S_IFREG
			written = perm&0o777 | 0o600
			if err := root.MkdirAll(filepath.Dir(target), 0o755); err != nil {
				return nil, 0, err
			}
			_ = root.Remove(target)
			f, err := root.OpenFile(target, os.O_CREATE|os.O_WRONLY|os.O_EXCL, 0o600)
			if err != nil {
				return nil, 0, err
			}
			n, err := io.Copy(f, tr)
			size += n
			if cerr := f.Close(); err == nil {
				err = cerr
			}
			if err != nil {
				return nil, 0, err
			}
			if err := root.Chmod(target, fs.FileMode(written)); err != nil {
				return nil, 0, err
			}
		case tar.TypeSymlink:
			ftype = syscall.S_IFLNK
			written = 0o777
			perm = 0o777
			if err := root.MkdirAll(filepath.Dir(target), 0o755); err != nil {
				return nil, 0, err
			}
			_ = root.Remove(target)
			if err := root.Symlink(hdr.Linkname, target); err != nil {
				return nil, 0, err
			}
		case tar.TypeLink:
			src := filepath.FromSlash(strings.TrimPrefix(path.Clean("/"+hdr.Linkname), "/"))
			_ = root.Remove(target)
			if err := root.Link(src, target); err != nil {
				return nil, 0, fmt.Errorf("hardlink %s: %w", rel, err)
			}
			continue // shares the inode (and its fixup) with src
		default:
			continue
		}
		if hdr.Typeflag != tar.TypeSymlink {
			_ = root.Chtimes(target, hdr.ModTime, hdr.ModTime)
		}
		size += 512
		if hdr.Uid != 0 || hdr.Gid != 0 || perm != written {
			fixups = append(fixups, fixup{path: "/" + rel, uid: hdr.Uid, gid: hdr.Gid, mode: ftype | perm})
		}
	}
}

// buildExt4 makes an ext4 image of the given size from dir, then applies
// fixups. It needs only e2fsprogs and unprivileged user namespaces.
func buildExt4(ctx context.Context, dir, out string, size int64, fixups []fixup) error {
	cmd := exec.CommandContext(ctx, "mke2fs", "-q", "-F", "-t", "ext4",
		"-m", "0", "-L", "ember", "-O", "^has_journal",
		"-E", "root_owner=0:0,lazy_itable_init=1,nodiscard",
		"-d", dir, out, fmt.Sprintf("%dk", size>>10))
	// Inside this namespace the current user is uid 0, so mke2fs records
	// every extracted file as owned by root.
	cmd.SysProcAttr = &syscall.SysProcAttr{
		Cloneflags:  syscall.CLONE_NEWUSER,
		UidMappings: []syscall.SysProcIDMap{{ContainerID: 0, HostID: os.Getuid(), Size: 1}},
		GidMappings: []syscall.SysProcIDMap{{ContainerID: 0, HostID: os.Getgid(), Size: 1}},
	}
	if b, err := cmd.CombinedOutput(); err != nil {
		return fmt.Errorf("mke2fs: %v: %s", err, strings.TrimSpace(string(b)))
	}
	if len(fixups) == 0 {
		return nil
	}
	var script bytes.Buffer
	for _, f := range fixups {
		if strings.ContainsAny(f.path, "\"\n\\") {
			continue // debugfs cannot quote these; keep root ownership
		}
		q := `"` + f.path + `"`
		if f.uid != 0 {
			fmt.Fprintf(&script, "sif %s uid %d\n", q, f.uid)
		}
		if f.gid != 0 {
			fmt.Fprintf(&script, "sif %s gid %d\n", q, f.gid)
		}
		fmt.Fprintf(&script, "sif %s mode 0%o\n", q, f.mode)
	}
	dbg := exec.CommandContext(ctx, "debugfs", "-w", "-f", "-", out)
	dbg.Stdin = &script
	b, err := dbg.CombinedOutput()
	if err != nil {
		return fmt.Errorf("debugfs: %v: %s", err, strings.TrimSpace(string(b)))
	}
	// debugfs reports per-command failures on stdout but exits 0.
	for _, line := range strings.Split(string(b), "\n") {
		if strings.Contains(line, "File not found") || strings.Contains(line, "invalid") {
			return fmt.Errorf("debugfs: %s", line)
		}
	}
	return nil
}
