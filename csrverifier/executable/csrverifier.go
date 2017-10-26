package executablecsrverifier

import (
	"errors"
	"os"
	"os/exec"
)

const (
	UserExecute os.FileMode = 1 << (6 - 3*iota)
	GroupExecute
	OtherExecute
)

func New(path string) (*ExecutableCSRVerifier, error) {
	fileInfo, err := os.Stat(path)
	if err != nil {
		return nil, err
	}

	fileMode := fileInfo.Mode()
	if fileMode.IsDir() {
		return nil, errors.New("CSR Verifier executable is a directory")
	}

	filePerm := fileMode.Perm()
	if filePerm&(UserExecute|GroupExecute|OtherExecute) == 0 {
		return nil, errors.New("CSR Verifier executable is not executable")
	}

	return &ExecutableCSRVerifier{executable: path}, nil
}

type ExecutableCSRVerifier struct {
	executable string
}

func (v *ExecutableCSRVerifier) Verify(data []byte) (bool, error) {
	cmd := exec.Command(v.executable)

	stdin, err := cmd.StdinPipe()
	if err != nil {
		return false, err
	}

	go func() {
		defer stdin.Close()
		stdin.Write(data)
	}()

	err = cmd.Run()
	if err != nil {
		// mask the executable error
		return false, nil
	}
	return true, err
}
