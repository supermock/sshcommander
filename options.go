package sshcommander

import "golang.org/x/crypto/ssh"

//SSHHost | Has an informations of host
type SSHHost struct {
	IP   string
	Port int
}

//SSHCredentials | Has an informations of credentials
type SSHCredentials struct {
	User     string
	Password string
	Keys     []string
}

//SSHCommanderOptions | Has an informations of options to SSHCommander
type SSHCommanderOptions struct {
	SSHHost         *SSHHost
	SSHCredentials  *SSHCredentials
	HostKeyCallBack *ssh.HostKeyCallback
	Output          bool
}

//SSHCommand | The command for run
type SSHCommand struct {
	Cmd string
	Env []string
}
