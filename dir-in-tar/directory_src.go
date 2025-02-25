package directory

import (
	"archive/tar"
	"compress/gzip"
	"context"
	"fmt"
	"io"
	"os"
	"strings"

	"github.com/containers/image/v5/internal/imagesource/impl"
	"github.com/containers/image/v5/internal/imagesource/stubs"
	"github.com/containers/image/v5/internal/manifest"
	"github.com/containers/image/v5/internal/private"
	"github.com/containers/image/v5/internal/signature"
	"github.com/containers/image/v5/types"
	"github.com/opencontainers/go-digest"
)

type dirInTarImageSource struct {
	impl.Compat
	impl.PropertyMethodsInitialize
	impl.DoesNotAffectLayerInfosForCopy
	stubs.NoGetBlobAtInitialize

	ref dirInTarReference
}

// newImageSource returns an ImageSource reading from an existing directory.
// The caller must call .Close() on the returned ImageSource.
func newImageSource(ref dirInTarReference) (private.ImageSource, error) {
	s := &dirInTarImageSource{
		PropertyMethodsInitialize: impl.PropertyMethods(impl.Properties{
			HasThreadSafeGetBlob: false,
		}),
		NoGetBlobAtInitialize: stubs.NoGetBlobAt(ref),

		ref: ref,
	}
	s.Compat = impl.AddCompat(s)
	return s, nil
}

func matchPath(header *tar.Header, path string) bool {
	name := strings.TrimPrefix(header.Name, "/")
	return name == path
}

func (s *dirInTarImageSource) readFile(path string) ([]byte, error) {
	bytes, err := s.readFileInner(path, true)
	if err != nil {
		if err == gzip.ErrHeader {
			return s.readFileInner(path, false)
		}
		return nil, err
	}
	return bytes, nil
}

func (s *dirInTarImageSource) readFileInner(path string, compressed bool) ([]byte, error) {
	f, err := os.Open(s.ref.resolvedTarPath)
	if err != nil {
		return nil, err
	}
	defer f.Close()

	var tr *tar.Reader
	if compressed {
		gr, err := gzip.NewReader(f)
		if err != nil {
			return nil, err
		}
		defer gr.Close()
		tr = tar.NewReader(gr)
	} else {
		tr = tar.NewReader(f)
	}

	for {
		header, err := tr.Next()
		if err == io.EOF {
			break
		}
		if err != nil {
			return nil, err
		}
		if matchPath(header, path) {
			return io.ReadAll(tr)
		}
	}
	return nil, os.ErrNotExist
}

type file struct {
	f    *os.File
	gr   *gzip.Reader
	tr   *tar.Reader
	size int64
}

func (f *file) Read(p []byte) (n int, err error) {
	if f.tr != nil {
		return f.tr.Read(p)
	}
	return 0, fmt.Errorf("file is not open")
}

func (f *file) Close() error {
	if f.gr != nil {
		if err := f.gr.Close(); err != nil {
			return err
		}
		f.gr = nil
	}
	if f.f != nil {
		if err := f.f.Close(); err != nil {
			return err
		}
		f.f = nil
	}
	return nil
}

func (f *file) Size() int64 {
	return f.size
}

func (s *dirInTarImageSource) openFile(path string) (*file, error) {
	f, err := s.openFileInner(path, true)
	if err != nil {
		if err == gzip.ErrHeader {
			return s.openFileInner(path, false)
		}
		return nil, err
	}
	return f, nil
}

func (s *dirInTarImageSource) openFileInner(path string, compressed bool) (*file, error) {
	f, err := os.Open(s.ref.resolvedTarPath)
	if err != nil {
		return nil, err
	}

	var tr *tar.Reader
	var gr *gzip.Reader
	if compressed {
		gr, err = gzip.NewReader(f)
		if err != nil {
			f.Close()
			return nil, err
		}
		tr = tar.NewReader(gr)
	} else {
		tr = tar.NewReader(f)
	}

	for {
		header, err := tr.Next()
		if err == io.EOF {
			break
		}
		if err != nil {
			f.Close()
			return nil, err
		}
		if matchPath(header, path) {
			return &file{f: f, gr: gr, tr: tr, size: header.Size}, nil
		}
	}
	f.Close()
	return nil, os.ErrNotExist
}

// Reference returns the reference used to set up this source, _as specified by the user_
// (not as the image itself, or its underlying storage, claims).  This can be used e.g. to determine which public keys are trusted for this image.
func (s *dirInTarImageSource) Reference() types.ImageReference {
	return s.ref
}

// Close removes resources associated with an initialized ImageSource, if any.
func (s *dirInTarImageSource) Close() error {
	return nil
}

// GetManifest returns the image's manifest along with its MIME type (which may be empty when it can't be determined but the manifest is available).
// It may use a remote (= slow) service.
// If instanceDigest is not nil, it contains a digest of the specific manifest instance to retrieve (when the primary manifest is a manifest list);
// this never happens if the primary manifest is not a manifest list (e.g. if the source never returns manifest lists).
func (s *dirInTarImageSource) GetManifest(ctx context.Context, instanceDigest *digest.Digest) ([]byte, string, error) {
	path, err := s.ref.manifestPath(instanceDigest)
	if err != nil {
		return nil, "", err
	}
	m, err := s.readFile(path)
	if err != nil {
		return nil, "", err
	}
	return m, manifest.GuessMIMEType(m), err
}

// GetBlob returns a stream for the specified blob, and the blob’s size (or -1 if unknown).
// The Digest field in BlobInfo is guaranteed to be provided, Size may be -1 and MediaType may be optionally provided.
// May update BlobInfoCache, preferably after it knows for certain that a blob truly exists at a specific location.
func (s *dirInTarImageSource) GetBlob(ctx context.Context, info types.BlobInfo, cache types.BlobInfoCache) (io.ReadCloser, int64, error) {
	path, err := s.ref.layerPath(info.Digest)
	if err != nil {
		return nil, -1, err
	}
	f, err := s.openFile(path)
	if err != nil {
		return nil, -1, err
	}
	return f, f.Size(), nil
}

// GetSignaturesWithFormat returns the image's signatures.  It may use a remote (= slow) service.
// If instanceDigest is not nil, it contains a digest of the specific manifest instance to retrieve signatures for
// (when the primary manifest is a manifest list); this never happens if the primary manifest is not a manifest list
// (e.g. if the source never returns manifest lists).
func (s *dirInTarImageSource) GetSignaturesWithFormat(ctx context.Context, instanceDigest *digest.Digest) ([]signature.Signature, error) {
	signatures := []signature.Signature{}
	for i := 0; ; i++ {
		path, err := s.ref.signaturePath(i, instanceDigest)
		if err != nil {
			return nil, err
		}
		sigBlob, err := s.readFile(path)
		if err != nil {
			if os.IsNotExist(err) {
				break
			}
			return nil, err
		}
		signature, err := signature.FromBlob(sigBlob)
		if err != nil {
			return nil, fmt.Errorf("parsing signature %q: %w", path, err)
		}
		signatures = append(signatures, signature)
	}
	return signatures, nil
}
