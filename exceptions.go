package sshcommander

import "fmt"

const (
	//ErrKeysNotFound | The keys not found on paths
	ErrKeysNotFound = "No keys found in past paths"
	//ErrMakeConnection | Failed create an connection
	ErrMakeConnection = "Failed to make an connection. %s"
	//ErrMakeSession | Failed create an session
	ErrMakeSession = "Failed to make an session. %s"
	//ErrPipeStdIn | Failed to pipe Standard In
	ErrPipeStdIn = "Failed to pipe Standard In. %s"
	//ErrRequestPseudoTerminal | Failed request pseudo terminal
	ErrRequestPseudoTerminal = "Request for pseudo terminal failed. %s"
	//ErrRequestShell | Request for shell failed
	ErrRequestShell = "Request for shell failed. %s"
)

// RunError stores the information about an exited remote command as reported by Wait.
type RunError struct {
	status int
	signal string
	msg    string
	lang   string
}

// ExitStatus returns the exit status of the remote command.
func (re RunError) ExitStatus() int {
	return re.status
}

// Signal returns the exit signal of the remote command if
// it was terminated violently.
func (re RunError) Signal() string {
	return re.signal
}

// Msg returns the exit message given by the remote command
func (re RunError) Msg() string {
	return re.msg
}

// Lang returns the language tag. See RFC 3066
func (re RunError) Lang() string {
	return re.lang
}

func (re RunError) Error() string {
	str := fmt.Sprintf("Process exited with status %v", re.status)
	if re.signal != "" {
		str += fmt.Sprintf(" from signal %v", re.signal)
	}
	if re.msg != "" {
		str += fmt.Sprintf(". Reason was: %v", re.msg)
	}
	return str
}
