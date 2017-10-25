package executablevalidator

import (
	"os/exec"
)

func NewExecutableValidator(path string) (*executableValidator, error) {
	return &executableValidator{executable: path}, nil
}

type executableValidator struct {
	executable string
}

func (v *executableValidator) Verify(data []byte) (bool, error) {
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
		return false, err
	} else {
		return true, err
	}
}
