package k8s

import (
	"errors"
	"fmt"
	"github.com/schollz/progressbar/v3"
	"github.com/spf13/cobra"
	"log/slog"
	"os"
	"path"
	client "sbom.observer/cli/pkg/client"
	"sbom.observer/cli/pkg/execx"
	"strings"
	"time"
)

var Debug = slog.Debug

func NewProgressBar(total int64, description string, debugging bool) *progressbar.ProgressBar {
	// disable when debugging
	if debugging {
		return progressbar.DefaultSilent(total, description)
	}

	return progressbar.Default(total, description)

}

func KubernetesCommand(cmd *cobra.Command, args []string) {
	isDebugging, _ := cmd.Flags().GetBool("debug")

	slog.Info("creating k8s snapshot using 'kubectl'")

	// kubectl get svc,nodes,pods,namespaces --all-namespaces -o json
	kubectlArgs := []string{"get", "svc,nodes,pods,namespaces", "--all-namespaces", "-o", "json"}

	slog.Debug(fmt.Sprintf("running 'kubectl %s'", strings.Join(kubectlArgs, " ")))
	output, extErr := execx.Exec("kubectl", kubectlArgs...)
	if extErr != nil {
		if errors.Is(extErr, execx.ErrNotFound) {
			slog.Error("kubectl not found in $PATH")
			// TODO: add download instructions
			os.Exit(1)
		}

		var extCmdErr *execx.ExternalCommandError
		if errors.As(extErr, &extCmdErr) {
			slog.Error("failed to create snapshot for cluster with 'kubectl'", "err", extErr)
			slog.Debug("error details", "message", extCmdErr.Message, "exitcode", extCmdErr.ExitCode, "stderr", extCmdErr.StdErr)
			os.Exit(1)
		}

		slog.Error("failed to get k8s snapshot with 'kubectl'", "err", extErr)
		os.Exit(1)
	}

	// TODO: validate output (parse, sanity check)

	// create output filename
	tempDir, err := os.MkdirTemp("", "observer-cli")
	if err != nil {
		slog.Error("failed to create temporary directory", "err", err)
		os.Exit(1)
	}

	//defer func() {
	//	err := os.RemoveAll(tempDir)
	//	if err != nil {
	//		slog.Error("failed to remove temporary directory", "err", err)
	//		os.Exit(1)
	//	}
	//	slog.Debug("removed temporary directory", "dir", tempDir)
	//}()

	snapshotFile := path.Join(tempDir, fmt.Sprintf("k8s-snapshot-%s.json", time.Now().Format("20060102-1504")))

	// write output to file
	err = os.WriteFile(snapshotFile, []byte(output), 0644)
	if err != nil {
		slog.Error("Error writing k8s snapshot to file", "filename", snapshotFile, "err", err)
		os.Exit(1)
	}

	slog.Debug(fmt.Sprintf("wrote k8s snapshot to file %s", snapshotFile))

	// upload candidates
	var filesToUpload []string
	filesToUpload = append(filesToUpload, snapshotFile)

	// create sboms
	if enabled, _ := cmd.Flags().GetBool("sbom"); enabled {
		// parse snapshot
		snapshot, err := ParseKubetclSnapshot([]byte(output))
		if err != nil {
			slog.Error("error parsing k8s snapshot", "err", err)
			os.Exit(1)
		}

		// extract images
		images := map[string]Image{}
		for _, resource := range snapshot.Resources {
			for _, image := range resource.Images {
				images[image.Name] = image
			}
		}

		slog.Info(fmt.Sprintf("creating SBOMs for %d images found in snapshot", len(images)))

		// create sboms
		sboms, err := createImageSboms(images, tempDir)
		if err != nil {
			slog.Error("error creating image sboms", "err", err)
			os.Exit(1)
		}

		filesToUpload = append(filesToUpload, sboms...)
	}

	// upload
	if enabled, _ := cmd.Flags().GetBool("upload"); enabled {
		c := client.NewObserverClient()

		progress := NewProgressBar(int64(len(filesToUpload)), "Uploading attestations", isDebugging)

		for _, file := range filesToUpload {
			err = c.UploadFile(file)
			if err != nil {
				slog.Error("error uploading file", "file", file, "err", err)
				os.Exit(1)
			}

			_ = progress.Add(1)
		}

		_ = progress.Finish()
		_ = progress.Clear()
	}
}

func createImageSboms(images map[string]Image, tempDir string) ([]string, error) {
	var sboms []string

	// update Trivy DB
	err := TrivyUpdateDb()
	if err != nil {
		return nil, err
	}

	// create sboms
	progress := NewProgressBar(int64(len(images)), "Scanning images", false)

NextImage:
	for _, image := range images {
		output := path.Join(tempDir, fmt.Sprintf("%s.sbom.cdx.json", sanitizeFilename(image.Name)))

		// TODO: caching (~/Librache/Caches/[app] or ~/.caches/[app]

		// TODO: this probably needs to be more robust
		pullable := image.RepositoryURL
		if image.Digest != "" {
			pullable = fmt.Sprintf("%s@%s", image.RepositoryURL, image.Digest)
		} else if image.Tag != "" {
			pullable = fmt.Sprintf("%s:%s", image.RepositoryURL, image.Tag)
		}

		err := CreateImageSbom(pullable, output)
		if err != nil {
			// user is already notified, so we just skip this image
			_ = progress.Add(1)
			continue NextImage
		}

		sboms = append(sboms, output)
		_ = progress.Add(1)
	}

	_ = progress.Finish()
	_ = progress.Clear()

	return sboms, nil
}

func Trivy(args ...string) (string, error) {
	slog.Debug(fmt.Sprintf("running 'trivy %s'", strings.Join(args, " ")))

	output, err := execx.Exec("trivy", args...)
	if err != nil {
		if errors.Is(err, execx.ErrNotFound) {
			slog.Error("Trivy not found in $PATH")
			slog.Info("Download and install Trivy from https://github.com/aquasecurity/trivy/releases")
			// TODO: add curl download instructions (use Github releases API?)
			os.Exit(1)
		}
	}

	return output, err
}

func CreateImageSbom(image string, output string) error {
	output, err := Trivy("image", "--skip-db-update", "--skip-java-db-update", "--format", "cyclonedx", "--output", output, image)
	if err != nil {
		var extCmdErr *execx.ExternalCommandError
		if errors.As(err, &extCmdErr) {
			slog.Error("failed to create SBOM for image with 'trivy' generator", "image", image, "exitcode", extCmdErr.ExitCode)
			_, _ = fmt.Fprint(os.Stderr, "-- Trivy output --\n")
			_, _ = fmt.Fprint(os.Stderr, extCmdErr.StdErr)
			_, _ = fmt.Fprint(os.Stderr, "\n------------------\n")
			return err
		}

		slog.Error("failed to create sbom for image using Trivy", "err", err)
		return err
	}

	return nil
}

func TrivyUpdateDb() error {
	slog.Debug("updating Trivy vulnerability database")

	_, extErr := Trivy("image", "--download-db-only")
	if extErr != nil {
		return fmt.Errorf("failed to update Trivy vulnerability database: %w", extErr)
	}

	_, extErr = Trivy("image", "--download-java-db-only")
	if extErr != nil {
		return fmt.Errorf("failed to update Trivy java vulnerability database: %w", extErr)
	}

	return nil
}

func sanitizeFilename(filename string) string {
	filename = strings.ReplaceAll(filename, "/", ".")
	filename = strings.ReplaceAll(filename, "@", "_")
	return filename
}
