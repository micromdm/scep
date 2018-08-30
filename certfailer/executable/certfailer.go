// Package executablecsrverifier defines the ExecutableCSRVerifier csrverifier.CSRVerifier.
package executablecertfailer

import (
	"bufio"
	"errors"
	"os"
	"os/exec"

	"github.com/go-kit/kit/log"
)

const (
	userExecute os.FileMode = 1 << (6 - 3*iota)
	groupExecute
	otherExecute
)

// New creates a executablecertfailer.ExecutableCertFailer.
func New(path string, logger log.Logger) (*ExecutableCertFailer, error) {
	fileInfo, err := os.Stat(path)
	if err != nil {
		return nil, err
	}

	fileMode := fileInfo.Mode()
	if fileMode.IsDir() {
		return nil, errors.New("Cert Failer executable is a directory")
	}

	filePerm := fileMode.Perm()
	if filePerm&(userExecute|groupExecute|otherExecute) == 0 {
		return nil, errors.New("Cert Failer executable is not executable")
	}

	return &ExecutableCertFailer{executable: path, logger: logger}, nil
}

// ExecutableCertFailer implements a certfailer.CertFailer.
// It executes a command, and passes it the raw decrypted CSR and an error message.
// The exit code is ignored.
type ExecutableCertFailer struct {
	executable string
	logger     log.Logger
}

func (v *ExecutableCertFailer) Fail(transactionID string, data []byte, errmsg string) (bool, error) {
	cmd := exec.Command(v.executable, errmsg)
	cmd.Env = append(os.Environ(), "TRANSACTIONID="+transactionID)

	stdin, err := cmd.StdinPipe()
	if err != nil {
		return false, err
	}
	go func() {
		defer stdin.Close()
		stdin.Write(data)
	}()

	stdout, err := cmd.StdoutPipe()
	if err != nil {
		return false, err
	}
	go func() {
		scanner := bufio.NewScanner(stdout)
		for scanner.Scan() {
			v.logger.Log("info", "failer stdout: "+scanner.Text())
		}
	}()

	stderr, err := cmd.StderrPipe()
	if err != nil {
		return false, err
	}
	go func() {
		scanner := bufio.NewScanner(stderr)
		for scanner.Scan() {
			v.logger.Log("info", "failer stderr: "+scanner.Text())
		}
	}()

	if err := cmd.Start(); err != nil {
		v.logger.Log("err", err)
		// mask the executable error
		return false, nil
	}

	if err := cmd.Wait(); err != nil {
		v.logger.Log("err", err)
		// mask the executable error
		return false, nil
	}
	return true, err
}
