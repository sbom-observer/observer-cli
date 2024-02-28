package execx

import (
	"bytes"
	"errors"
	"fmt"
	"os"
	"os/exec"
)

var ErrNotFound = exec.ErrNotFound

type ExternalCommandError struct {
	Message  string
	ExitCode int
	StdErr   string
}

func (e *ExternalCommandError) Error() string {
	return e.Message
}

func Exec(command string, args ...string) (string, error) {
	cmd := exec.Command(command, args...)

	// Buffer to capture stdout and stderr
	var stdoutBuf, stderrBuf bytes.Buffer
	cmd.Stdout = &stdoutBuf
	cmd.Stderr = &stderrBuf

	// forward the current environment
	cmd.Env = os.Environ()

	// Execute the command
	err := cmd.Run()
	if err != nil {
		var exerr *exec.ExitError
		if errors.As(err, &exerr) {
			return "", &ExternalCommandError{
				Message:  fmt.Sprintf("the command exited unsuccessfully: %d\n", exerr.ExitCode()),
				ExitCode: exerr.ExitCode(),
				StdErr:   stderrBuf.String(),
			}
		}

		// TODO: handle binary not found
		if errors.Is(err, exec.ErrNotFound) {
			return "", ErrNotFound
		}

		// If there's an error, return it along with stderr output
		//return fmt.Errorf("Error executing trivy: %v, stderr: %s", err, stderrBuf.String())
		return "", &ExternalCommandError{
			Message:  fmt.Sprintf("the command exited unsuccessfully: %+v\n", err),
			ExitCode: 0,
			StdErr:   stderrBuf.String(),
		}
	}

	//fmt.Printf("stodout: %s\n", stdoutBuf.String())
	//fmt.Printf("stderr: %s\n", stderrBuf.String())
	//fmt.Println(".......................")

	return stdoutBuf.String(), nil
}
