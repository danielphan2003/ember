// Package image turns OCI images into bootable ext4 root filesystems and
// caches them by digest.
//
// A cached image is built once: the layers are flattened into one tar, the
// guest agent is added at /.ember/agent, and mke2fs writes the filesystem
// straight from the tar (no root, no loop mounts). Each VM then boots from a
// copy-on-write clone of that file.
package image

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"net/http"
	"net/netip"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"sync"
	"syscall"
	"time"

	"github.com/google/go-containerregistry/pkg/authn"
	"github.com/google/go-containerregistry/pkg/name"
	v1 "github.com/google/go-containerregistry/pkg/v1"
	"github.com/google/go-containerregistry/pkg/v1/mutate"
	"github.com/google/go-containerregistry/pkg/v1/remote"
	"golang.org/x/sync/singleflight"
)

// AgentPath is where the guest agent lives inside every rootfs. The kernel
// starts it as init.
const AgentPath = "/.ember/agent"

// Image is a cached, bootable root filesystem.
type Image struct {
	Ref        string
	Digest     string
	RootFS     string
	Env        []string
	WorkingDir string
	User       string
}

type meta struct {
	Ref        string   `json:"ref"`
	Digest     string   `json:"digest"`
	Env        []string `json:"env"`
	WorkingDir string   `json:"working_dir"`
	User       string   `json:"user"`
}

type refEntry struct {
	Digest  string    `json:"digest"` // the platform image's manifest
	Head    string    `json:"head"`   // what the tag pointed at (often an index)
	Checked time.Time `json:"checked"`
}

// Store caches images under Dir.
type Store struct {
	Dir     string
	Agent   []byte        // the ember-agent binary to install in each rootfs
	Refresh time.Duration // how long a tag's digest is trusted
	MinGiB  int           // minimum filesystem size
	MaxMiB  int           // largest unpacked image accepted

	group     singleflight.Group
	mu        sync.Mutex
	agentOnce sync.Once
	agentID   string
}

func (s *Store) refsPath() string { return filepath.Join(s.Dir, "refs.json") }

func (s *Store) loadRefs() map[string]refEntry {
	refs := map[string]refEntry{}
	if b, err := os.ReadFile(s.refsPath()); err == nil {
		_ = json.Unmarshal(b, &refs)
	}
	return refs
}

func (s *Store) saveRef(ref string, e refEntry) {
	s.mu.Lock()
	defer s.mu.Unlock()
	refs := s.loadRefs()
	refs[ref] = e
	b, _ := json.MarshalIndent(refs, "", "  ")
	tmp := s.refsPath() + ".tmp"
	if os.WriteFile(tmp, b, 0o644) == nil {
		_ = os.Rename(tmp, s.refsPath())
	}
}

// dirFor names an image's cache directory after its digest and the agent
// baked into it, so upgrading ember rebuilds images with the new agent.
func (s *Store) dirFor(digest string) string {
	s.agentOnce.Do(func() {
		sum := sha256.Sum256(s.Agent)
		s.agentID = hex.EncodeToString(sum[:6])
	})
	return filepath.Join(s.Dir, strings.ReplaceAll(digest, ":", "-")+"-agent-"+s.agentID)
}

// Ensure returns the cached image for ref, pulling and building it if
// needed. progress receives human-readable status lines for the job log.
func (s *Store) Ensure(ctx context.Context, ref string, progress func(string)) (*Image, error) {
	r, err := name.ParseReference(ref)
	if err != nil {
		return nil, fmt.Errorf("image %q: %w", ref, err)
	}
	key := r.Name()

	// Digest references never change; tags are re-checked after Refresh.
	if d, ok := r.(name.Digest); ok {
		if img, err := s.load(d.DigestStr()); err == nil {
			return img, nil
		}
	} else if e, ok := s.loadRefs()[key]; ok && time.Since(e.Checked) < s.Refresh {
		if img, err := s.load(e.Digest); err == nil {
			return img, nil
		}
	}

	// The pull is shared by every job waiting for this image, so one job's
	// cancellation must not abort it.
	ch := s.group.DoChan(key, func() (any, error) {
		pullCtx, cancel := context.WithTimeout(context.WithoutCancel(ctx), 30*time.Minute)
		defer cancel()
		// A HEAD request is enough to see that a tag has not moved, and
		// registries such as Docker Hub do not count it against pull limits.
		if e, ok := s.loadRefs()[key]; ok && e.Head != "" {
			if desc, err := remote.Head(r, s.remoteOptions(pullCtx)...); err == nil && desc.Digest.String() == e.Head {
				if img, err := s.load(e.Digest); err == nil {
					s.saveRef(key, refEntry{Digest: e.Digest, Head: e.Head, Checked: time.Now()})
					return img, nil
				}
			}
		}
		return s.pull(pullCtx, r, progress)
	})
	var res singleflight.Result
	select {
	case res = <-ch:
	case <-ctx.Done():
		return nil, ctx.Err()
	}
	v, err := res.Val, res.Err
	if err != nil {
		// A registry outage should not stop jobs whose image is cached.
		if e, ok := s.loadRefs()[key]; ok {
			if img, lerr := s.load(e.Digest); lerr == nil {
				progress(fmt.Sprintf("registry unreachable (%v); using cached %s", err, e.Digest))
				return img, nil
			}
		}
		return nil, err
	}
	return v.(*Image), nil
}

func (s *Store) load(digest string) (*Image, error) {
	dir := s.dirFor(digest)
	b, err := os.ReadFile(filepath.Join(dir, "meta.json"))
	if err != nil {
		return nil, err
	}
	var m meta
	if err := json.Unmarshal(b, &m); err != nil {
		return nil, err
	}
	rootfs := filepath.Join(dir, "rootfs.ext4")
	if _, err := os.Stat(rootfs); err != nil {
		return nil, err
	}
	now := time.Now()
	_ = os.Chtimes(dir, now, now) // marks the image as recently used
	return &Image{Ref: m.Ref, Digest: m.Digest, RootFS: rootfs, Env: m.Env, WorkingDir: m.WorkingDir, User: m.User}, nil
}

func (s *Store) pull(ctx context.Context, r name.Reference, progress func(string)) (*Image, error) {
	desc, err := remote.Get(r, s.remoteOptions(ctx)...)
	if err != nil {
		return nil, fmt.Errorf("resolve %s: %w", r.Name(), err)
	}
	head := desc.Digest.String()
	img, err := desc.Image() // picks the platform from an index
	if err != nil {
		return nil, fmt.Errorf("resolve %s: %w", r.Name(), err)
	}
	digest, err := img.Digest()
	if err != nil {
		return nil, err
	}
	key := r.Name()
	if cached, err := s.load(digest.String()); err == nil {
		s.saveRef(key, refEntry{Digest: digest.String(), Head: head, Checked: time.Now()})
		return cached, nil
	}

	progress(fmt.Sprintf("pulling %s (%s)", r.Name(), digest))
	start := time.Now()
	cfg, err := img.ConfigFile()
	if err != nil {
		return nil, err
	}

	if err := os.MkdirAll(s.Dir, 0o755); err != nil {
		return nil, err
	}
	tmp, err := os.MkdirTemp(s.Dir, ".build-")
	if err != nil {
		return nil, err
	}
	defer os.RemoveAll(tmp)

	tree := filepath.Join(tmp, "tree")
	if err := os.Mkdir(tree, 0o755); err != nil {
		return nil, err
	}
	rc := mutate.Extract(img)
	fixups, size, err := extract(rc, tree, int64(s.MaxMiB)<<20)
	rc.Close()
	if err != nil {
		return nil, fmt.Errorf("unpack %s: %w", r.Name(), err)
	}
	if err := s.installAgent(tree); err != nil {
		return nil, err
	}
	progress(fmt.Sprintf("building root filesystem (%d MiB, %d ownership fixups)", size>>20, len(fixups)))

	// Leave room for the job: at least MinGiB, and half again the content.
	fsBytes := max(int64(s.MinGiB)<<30, size+size/2+(512<<20))
	if err := buildExt4(ctx, tree, filepath.Join(tmp, "rootfs.ext4"), fsBytes, fixups); err != nil {
		return nil, err
	}
	if err := os.RemoveAll(tree); err != nil {
		return nil, err
	}

	m := meta{Ref: r.Name(), Digest: digest.String(), Env: cfg.Config.Env, WorkingDir: cfg.Config.WorkingDir, User: cfg.Config.User}
	b, _ := json.MarshalIndent(m, "", "  ")
	if err := os.WriteFile(filepath.Join(tmp, "meta.json"), b, 0o644); err != nil {
		return nil, err
	}
	final := s.dirFor(digest.String())
	if err := os.Rename(tmp, final); err != nil && !errors.Is(err, os.ErrExist) {
		// Another process may have won the race; use its copy if it is whole.
		if _, lerr := s.load(digest.String()); lerr != nil {
			return nil, err
		}
	}
	s.saveRef(key, refEntry{Digest: digest.String(), Head: head, Checked: time.Now()})
	progress(fmt.Sprintf("image ready in %s", time.Since(start).Round(100*time.Millisecond)))
	return s.load(digest.String())
}

// installAgent puts the guest agent at /.ember/agent.
func (s *Store) installAgent(tree string) error {
	if len(s.Agent) == 0 {
		return errors.New("ember was built without the guest agent (run `just build`)")
	}
	// Through os.Root: the image may have planted symlinks that would
	// otherwise redirect this write onto the host.
	root, err := os.OpenRoot(tree)
	if err != nil {
		return err
	}
	defer root.Close()
	if err := root.RemoveAll(".ember"); err != nil {
		return err
	}
	if err := root.Mkdir(".ember", 0o755); err != nil {
		return err
	}
	return root.WriteFile(".ember/agent", s.Agent, 0o755)
}

// Prune removes cached images not used within keep. It returns the digests
// it removed.
func (s *Store) Prune(keep time.Duration) ([]string, error) {
	entries, err := os.ReadDir(s.Dir)
	if errors.Is(err, os.ErrNotExist) {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	var removed []string
	for _, e := range entries {
		if !e.IsDir() {
			continue
		}
		info, err := e.Info()
		if err != nil {
			continue
		}
		stale := time.Since(info.ModTime()) > keep
		// Leftover build directories from a crash are always stale after a day.
		if strings.HasPrefix(e.Name(), ".build-") {
			stale = time.Since(info.ModTime()) > 24*time.Hour
		}
		if stale {
			if err := os.RemoveAll(filepath.Join(s.Dir, e.Name())); err == nil {
				removed = append(removed, e.Name())
			}
		}
	}
	return removed, nil
}

func (s *Store) remoteOptions(ctx context.Context) []remote.Option {
	return []remote.Option{
		remote.WithContext(ctx),
		remote.WithPlatform(v1.Platform{OS: "linux", Architecture: runtime.GOARCH}),
		remote.WithAuthFromKeychain(authn.DefaultKeychain),
		remote.WithTransport(publicOnlyTransport),
	}
}

// publicOnlyTransport refuses to connect to loopback, private, CGNAT,
// link-local and other non-public addresses. Image references come from job
// definitions, so without this a job could make the host send requests to
// its own services, the LAN or the tailnet.
var publicOnlyTransport = func() http.RoundTripper {
	t := remote.DefaultTransport.(*http.Transport).Clone()
	d := &net.Dialer{Timeout: 30 * time.Second, KeepAlive: 30 * time.Second, Control: refuseNonPublic}
	t.DialContext = d.DialContext
	return t
}()

func refuseNonPublic(_, address string, _ syscall.RawConn) error {
	host, _, err := net.SplitHostPort(address)
	if err != nil {
		return err
	}
	ip, err := netip.ParseAddr(host)
	if err != nil {
		return err
	}
	if !PublicAddr(ip) {
		return fmt.Errorf("refusing to contact non-public address %s", ip)
	}
	return nil
}

var nonPublic = []netip.Prefix{
	netip.MustParsePrefix("0.0.0.0/8"), netip.MustParsePrefix("100.64.0.0/10"),
	netip.MustParsePrefix("192.0.0.0/24"), netip.MustParsePrefix("198.18.0.0/15"),
	netip.MustParsePrefix("64:ff9b::/96"),
}

// PublicAddr reports whether ip is a globally routable unicast address.
func PublicAddr(ip netip.Addr) bool {
	ip = ip.Unmap()
	if !ip.IsGlobalUnicast() || ip.IsPrivate() {
		return false
	}
	for _, p := range nonPublic {
		if p.Contains(ip) {
			return false
		}
	}
	return true
}
