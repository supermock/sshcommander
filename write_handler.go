package sshcommander

import (
	"bytes"
	"fmt"
	"io"
	"sync"
)

var sudoPasswordPrompt = []byte{115, 117, 100, 111, 95, 112, 97, 115, 115, 119, 111, 114, 100}

type writeHandler struct {
	b            bytes.Buffer
	stdin        io.Writer
	sshCommander *SSHCommander
	m            sync.Mutex
}

func (w *writeHandler) Write(p []byte) (int, error) {
	if bytes.Contains(p, sudoPasswordPrompt) {
		w.stdin.Write([]byte(w.sshCommander.password + "\n"))
		return len(p), nil
	}

	w.m.Lock()
	defer w.m.Unlock()

	if w.sshCommander.output {
		fmt.Print(string(p))
	}

	return w.b.Write(p)
}
