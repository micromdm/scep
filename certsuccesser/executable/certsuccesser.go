// Package executablecsrverifier defines the ExecutableCSRVerifier csrverifier.CSRVerifier.
package executablecertsuccesser

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

// New creates a executablecertsuccesser.ExecutableCertSuccesser.
func New(path string, logger log.Logger) (*ExecutableCertSuccesser, error) {
	fileInfo, err := os.Stat(path)
	if err != nil {
		return nil, err
	}

	fileMode := fileInfo.Mode()
	if fileMode.IsDir() {
		return nil, errors.New("Cert Successer executable is a directory")
	}

	filePerm := fileMode.Perm()
	if filePerm&(userExecute|groupExecute|otherExecute) == 0 {
		return nil, errors.New("Cert Successer executable is not executable")
	}

	return &ExecutableCertSuccesser{executable: path, logger: logger}, nil
}

// ExecutableCertSuccesser implements a certsuccesser.CertSuccesser.
// It executes a command, and passes it the raw decrypted CSR and cert.
// If the command exit code is 0, the cert can be returned to the client.
// In any other cases, the cert is failed and the client gets an error.
type ExecutableCertSuccesser struct {
	executable string
	logger     log.Logger
}

func (v *ExecutableCertSuccesser) Success(transactionID string, data []byte, certFilename string) (bool, error) {
	cmd := exec.Command(v.executable, certFilename)
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
			v.logger.Log("info", "successer stdout: "+scanner.Text())
		}
	}()

	stderr, err := cmd.StderrPipe()
	if err != nil {
		return false, err
	}
	go func() {
		scanner := bufio.NewScanner(stderr)
		for scanner.Scan() {
			v.logger.Log("info", "successer stderr: "+scanner.Text())
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
