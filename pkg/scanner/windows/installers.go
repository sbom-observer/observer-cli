package windows

import (
	"bytes"
	"fmt"
	"io"
	"os"
	"path/filepath"

	"github.com/sbom-observer/observer-cli/pkg/log"
)

// ArchiveType represents the type of embedded archive
type ArchiveType string

const (
	ArchiveCAB = "cab"
	ArchiveZIP = "zip"
)

// Archive signatures
var (
	CABSignature = []byte("MSCF")       // CAB header signature
	ZIPSignature = []byte("PK\x03\x04") // ZIP local file header signature
)

type CleanupFunc func()

// extractEmbeddedArchives detects and carves embedded archives from a Windows installer executable.
// The function writes the carved archives to a new temporary directory and returns the absolute paths
// to the carved files along with a cleanup function to delete the temporary directory.
//
// It avoids reading the entire installer into memory by scanning the file in chunks. The file may be
// read multiple times; the OS page cache should make this efficient.
func extractEmbeddedArchives(filePath string) ([]string, CleanupFunc, error) {
	// Stat for file size
	fi, err := os.Stat(filePath)
	if err != nil {
		return nil, nil, fmt.Errorf("failed to stat file: %w", err)
	}
	totalSize := fi.Size()

	// Temp dir for carved archives
	tempDir, cleanup, err := CreateTempDir()
	if err != nil {
		return nil, nil, fmt.Errorf("failed to create temp dir: %w", err)
	}

	// Find offsets for signatures using chunked scanning
	cabOffsets, err := scanSignatureOffsets(filePath, CABSignature)
	if err != nil {
		cleanup()
		return nil, nil, fmt.Errorf("failed to scan CAB signatures: %w", err)
	}
	zipOffsets, err := scanSignatureOffsets(filePath, ZIPSignature)
	if err != nil {
		cleanup()
		return nil, nil, fmt.Errorf("failed to scan ZIP signatures: %w", err)
	}

	carved := make([]string, 0, len(cabOffsets)+len(zipOffsets))

	// helper to carve [start,end) range to file
	carveRange := func(start, end int64, ext string, index int) (string, error) {
		size := end - start
		if size <= 0 {
			return "", fmt.Errorf("invalid carve size: %d", size)
		}

		in, err := os.Open(filePath)
		if err != nil {
			return "", fmt.Errorf("failed to open source file: %w", err)
		}
		defer in.Close()

		if _, err := in.Seek(start, io.SeekStart); err != nil {
			return "", fmt.Errorf("failed to seek to %d: %w", start, err)
		}

		name := fmt.Sprintf("%s_%d_%d.%s", ext, index, start, ext)
		outPath := filepath.Join(tempDir, name)
		out, err := os.OpenFile(outPath, os.O_CREATE|os.O_TRUNC|os.O_WRONLY, 0644)
		if err != nil {
			return "", fmt.Errorf("failed to create carved file: %w", err)
		}
		defer func() { _ = out.Close() }()

		written, err := io.CopyN(out, in, size)
		if err != nil {
			return "", fmt.Errorf("failed to write carved data: %w", err)
		}
		if written != size {
			return "", fmt.Errorf("short write while carving: wrote %d expected %d", written, size)
		}

		return outPath, nil
	}

	// carve CABs (end at next CAB or EOF)
	for i, start := range cabOffsets {
		end := totalSize
		if i+1 < len(cabOffsets) {
			end = cabOffsets[i+1]
		}
		p, err := carveRange(start, end, string(ArchiveCAB), i)
		if err != nil {
			log.Error("failed to carve CAB archive", "file", filePath, "offset", start, "error", err)
			continue
		}
		log.Debug("carved archive", "type", string(ArchiveCAB), "offset", start, "size", end-start, "path", p)
		carved = append(carved, p)
	}

	// carve ZIPs (end at next ZIP or EOF)
	for i, start := range zipOffsets {
		end := totalSize
		if i+1 < len(zipOffsets) {
			end = zipOffsets[i+1]
		}
		p, err := carveRange(start, end, string(ArchiveZIP), i)
		if err != nil {
			log.Error("failed to carve ZIP archive", "file", filePath, "offset", start, "error", err)
			continue
		}
		log.Debug("carved archive", "type", string(ArchiveZIP), "offset", start, "size", end-start, "path", p)
		carved = append(carved, p)
	}

	log.Debug("detected embedded archives",
		"file", filePath,
		"total_archives", len(carved),
		"cab_count", len(cabOffsets),
		"zip_count", len(zipOffsets))

	return carved, cleanup, nil
}

// scanSignatureOffsets finds absolute offsets of a signature in a file using chunked scanning with overlap.
func scanSignatureOffsets(filePath string, signature []byte) ([]int64, error) {

	f, err := os.Open(filePath)
	if err != nil {
		return nil, fmt.Errorf("failed to open file: %w", err)
	}
	defer f.Close()

	const chunkSize = 1 << 20 // 1 MiB
	overlap := len(signature) - 1
	if overlap < 0 {
		overlap = 0
	}
	buf := make([]byte, chunkSize+overlap)

	var (
		offsets []int64
		carry   = 0
		pos     int64
	)

	for {
		n, err := f.Read(buf[carry:])
		if n == 0 && err == io.EOF {
			break
		}
		if err != nil && err != io.EOF {
			return nil, fmt.Errorf("read error: %w", err)
		}

		searchLen := carry + n
		if searchLen == 0 {
			break
		}
		windowStart := pos - int64(carry)
		search := buf[:searchLen]

		p := 0
		for {
			idx := bytes.Index(search[p:], signature)
			if idx < 0 {
				break
			}
			abs := windowStart + int64(p+idx)
			offsets = append(offsets, abs)
			p += idx + 1
		}

		// prepare overlap for next chunk
		if searchLen > overlap {
			copy(buf[:overlap], search[searchLen-overlap:searchLen])
			carry = overlap
		} else {
			copy(buf[:searchLen], search[:searchLen])
			carry = searchLen
		}

		pos += int64(n)
		if err == io.EOF {
			break
		}
	}

	return offsets, nil
}
