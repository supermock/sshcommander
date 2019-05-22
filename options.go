package sshcommander

import "golang.org/x/crypto/ssh"

//Host | Has an informations of host
type Host struct {
	IP   string
	Port int
}

//Credentials | Has an informations of credentials
type Credentials struct {
	User     string
	Password string
	Keys     []string
}

//Options | Has an informations of options to SSHCommander
type Options struct {
	Host            *Host
	Credentials     *Credentials
	HostKeyCallBack *ssh.HostKeyCallback
	Output          bool
}

//Command | The command for run
type Command struct {
	Cmd string
	Env []string
}
