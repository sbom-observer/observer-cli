package windows

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestExtractEmbeddedArchives_VCRedist(t *testing.T) {
	// Locate test installer (VC_redist.x64.exe) which is known to contain two CAB files
	installerPath := filepath.Join("..", "..", "..", "testdata", "windows", "vc-redist", "VC_redist.x64.exe")

	if _, err := os.Stat(installerPath); err != nil {
		t.Fatalf("missing test installer at %s: %v", installerPath, err)
	}

	paths, cleanup, err := extractEmbeddedArchives(installerPath)
	defer func() {
		if cleanup != nil {
			cleanup()
		}
	}()

	if err != nil {
		t.Fatalf("extractEmbeddedArchives error: %v", err)
	}

	if len(paths) != 2 {
		t.Fatalf("expected 2 carved archives, got %d (paths=%v)", len(paths), paths)
	}

	for _, p := range paths {
		if !strings.HasSuffix(strings.ToLower(p), ".cab") {
			t.Errorf("expected carved archive to have .cab extension: %s", p)
		}
		info, statErr := os.Stat(p)
		if statErr != nil {
			t.Errorf("carved file does not exist: %s: %v", p, statErr)
			continue
		}
		if info.Size() == 0 {
			t.Errorf("carved file has zero size: %s", p)
		}
	}
}
