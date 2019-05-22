package sshcommander

import (
	"errors"
	"fmt"
	"io/ioutil"
	"log"
	"regexp"
	"strings"
	"time"

	"golang.org/x/crypto/ssh"
)

var matchSudoCommand = regexp.MustCompile(`\bsudo\b\s`)

//SSHCommander | SSHCommander
type SSHCommander struct {
	options    Options
	connection *ssh.Client
}

//NewSSHCommander | Make an new instance of SSHCommander
func NewSSHCommander(options *Options) (*SSHCommander, error) {
	if options.Host != nil {
		if options.Host.IP == "" {
			return nil, errors.New("Please pass Host.IP")
		}

		if options.Host.Port == 0 {
			options.Host.Port = 22
		}
	} else {
		return nil, errors.New("Please pass Host option")
	}

	if options.Credentials != nil {
		if options.Credentials.User == "" {
			return nil, errors.New("Please pass Credentials.User")
		}

		if len(options.Credentials.Keys) == 0 && options.Credentials.Password == "" {
			return nil, errors.New("Please pass Credentials.Keys or Credentials.Password")
		}
	} else {
		return nil, errors.New("Please pass Credentials option")
	}

	if options.HostKeyCallBack == nil {
		hostKeyCallback := ssh.InsecureIgnoreHostKey()

		options.HostKeyCallBack = &hostKeyCallback
	}

	return &SSHCommander{
		options: *options,
	}, nil
}

//NewSSHCommand | Make an new instance of SSHCommand
func NewSSHCommand(command string, environments []string) *Command {
	return &Command{
		Cmd: command,
		Env: environments,
	}
}

//SetOptions | Change SSHCommander options and reset connection with remote host
func (sshCommander *SSHCommander) SetOptions(options *Options) error {
	if options.Host != nil {
		if options.Host.IP != "" {
			sshCommander.options.Host.IP = options.Host.IP
		}

		if options.Host.Port != 0 {
			sshCommander.options.Host.Port = options.Host.Port
		}
	}

	if options.Credentials != nil {
		if options.Credentials.User != "" {
			sshCommander.options.Credentials.User = options.Credentials.User
		}

		if options.Credentials.Password != "" {
			sshCommander.options.Credentials.Password = options.Credentials.Password
		}

		if len(options.Credentials.Keys) != 0 {
			sshCommander.options.Credentials.Keys = options.Credentials.Keys
		}
	}

	if options.HostKeyCallBack != nil {
		hostKeyCallBack := *options.HostKeyCallBack

		sshCommander.options.HostKeyCallBack = &hostKeyCallBack
	}

	return sshCommander.Reconnect()
}

//Connect make connection from SSH
func (sshCommander *SSHCommander) Connect() (err error) {
	config := &ssh.ClientConfig{
		User:            sshCommander.options.Credentials.User,
		Auth:            []ssh.AuthMethod{},
		HostKeyCallback: *sshCommander.options.HostKeyCallBack,
	}

	if len(sshCommander.options.Credentials.Keys) == 0 {
		config.Auth = append(config.Auth, ssh.Password(sshCommander.options.Credentials.Password))
	} else {
		var signers []ssh.Signer

		if signers, err = sshCommander.loadKeys(); err != nil {
			return
		}

		config.Auth = append(config.Auth, ssh.PublicKeys(signers...))
	}

	if sshCommander.connection, err = ssh.Dial("tcp",
		fmt.Sprintf("%s:%d", sshCommander.options.Host.IP, sshCommander.options.Host.Port),
		config,
	); err != nil {
		err = fmt.Errorf(ErrMakeConnection, err.Error())
	}

	return
}

//Disconnect | Close the SSH connection
func (sshCommander *SSHCommander) Disconnect() (err error) {
	if sshCommander.connection != nil {
		err = sshCommander.connection.Close()
	}

	return
}

//Reconnect | Close the SSH connection and reopen
func (sshCommander *SSHCommander) Reconnect() error {
	if err := sshCommander.Disconnect(); err != nil {
		return err
	}

	return sshCommander.Connect()
}

//Run | Run an command
func (sshCommander *SSHCommander) Run(sshCommand *Command) (output string, err error) {
	if sshCommander.connection == nil {
		err = errors.New("Please before run SSHCommander.Connect()")
		return
	}

	if matchSudoCommand.MatchString(sshCommand.Cmd) && sshCommander.options.Credentials.Password == "" {
		err = errors.New("You cannot execute commands with sudo, pass SSHCredentials.Password for use it")
		return
	}

	if sshCommander.options.Output {
		fmt.Println("$", sshCommand.Cmd)
	}

	var (
		session *ssh.Session
		modes   = ssh.TerminalModes{
			ssh.ECHO:          0,     // disable echoing
			ssh.TTY_OP_ISPEED: 14400, // input speed = 14.4kbaud
			ssh.TTY_OP_OSPEED: 14400, // output speed = 14.4kbaud
		}
	)

	if session, err = sshCommander.connection.NewSession(); err != nil {
		err = fmt.Errorf(ErrMakeSession, err.Error())
		return
	}
	defer session.Close()

	if err = session.RequestPty("xterm", 80, 40, modes); err != nil {
		err = fmt.Errorf(ErrRequestPseudoTerminal, err.Error())
		return
	}

	w := &writeHandler{
		sshCommander: sshCommander,
	}

	w.stdin, err = session.StdinPipe()
	if err != nil {
		err = fmt.Errorf(ErrPipeStdIn, err.Error())
		return
	}

	session.Stdout = w
	session.Stderr = w

	cmd := sshCommand.Cmd

	// -S Writes the prompt to StdErr and reads the password from StdIn
	// -v update user's timestamp without running a command
	// -p specify the prompt.
	if matchSudoCommand.MatchString(cmd) {
		cmd = fmt.Sprintf("sudo -Svp %s; %s", sudoPasswordPrompt, cmd)
	}

	if len(sshCommand.Env) > 0 {
		cmd = fmt.Sprintf("%s && %s", strings.Join(sshCommand.Env, " "), cmd)
	}

	if err := session.Start(cmd); err != nil {
		err = fmt.Errorf(ErrRequestShell, err.Error())
	}

	err = session.Wait()
	output = strings.TrimSpace(w.b.String())

	if err != nil {
		if exitError, ok := err.(*ssh.ExitError); ok {
			runError := &RunError{
				lang:   exitError.Waitmsg.Lang(),
				msg:    output,
				signal: exitError.Waitmsg.Signal(),
				status: exitError.Waitmsg.ExitStatus(),
			}

			err = runError
		}
	}

	return
}

//RunCmd | Alis for Run
func (sshCommander *SSHCommander) RunCmd(command string, args ...interface{}) (string, error) {
	if len(args) > 0 {
		command = fmt.Sprintf(command, args...)
	}

	return sshCommander.Run(NewSSHCommand(command, nil))
}

//RunEnv | Alis for Run
func (sshCommander *SSHCommander) RunEnv(command string, args ...interface{}) func([]string) (string, error) {
	if len(args) > 0 {
		command = fmt.Sprintf(command, args...)
	}

	return func(environments []string) (string, error) {
		return sshCommander.Run(NewSSHCommand(command, environments))
	}
}

//Reboot | Restart remote machine and return if connection is ok
//If retries is 0 retries is infinity.
func (sshCommander *SSHCommander) Reboot(retries int) error {
	if _, err := sshCommander.Run(NewSSHCommand("sudo reboot", nil)); err != nil {
		if _, ok := err.(*ssh.ExitMissingError); !ok {
			return fmt.Errorf("Failed to reboot remote machine. Err: %s", err)
		}
	}

	sshCommander.Disconnect()

	attempts := 0
	for {
		if sshCommander.options.Output {
			fmt.Println("Waiting rebooting remote machine... Retrying in 5s")
		}

		time.Sleep(5 * time.Second)

		if sshCommander.Connect() == nil {
			break
		}

		if retries != 0 {
			attempts++
			if attempts > retries {
				return errors.New("Number of attempts reached")
			}
		}
	}

	return nil
}

//PowerOff | PowerOff remote machine
func (sshCommander *SSHCommander) PowerOff() error {
	if _, err := sshCommander.Run(NewSSHCommand("sudo poweroff", nil)); err != nil {
		if _, ok := err.(*ssh.ExitMissingError); !ok {
			return fmt.Errorf("Failed to poweroff remote machine. Err: %s", err)
		}
	}

	sshCommander.Disconnect()

	return nil
}

func (sshCommander *SSHCommander) loadKeys() ([]ssh.Signer, error) {
	signers := make([]ssh.Signer, 0)

	for k := 0; k < len(sshCommander.options.Credentials.Keys); k++ {
		keyFile, err := ioutil.ReadFile(sshCommander.options.Credentials.Keys[k])
		if err == nil {
			if signer, err := ssh.ParsePrivateKey(keyFile); err == nil {
				signers = append(signers, signer)
			} else {
				return signers, err
			}
		}
	}

	if len(signers) == 0 {
		return signers, errors.New(ErrKeysNotFound)
	}

	return signers, nil
}

//LoadSSHHostKey | Load an Host Key and return HostKeyCallBack (Generally is in /etc/ssh/ssh_host_dsa_key)
func LoadSSHHostKey(path string) *ssh.HostKeyCallback {
	var hostKeyCallBack ssh.HostKeyCallback
	keyFile, err := ioutil.ReadFile(path)
	if err == nil {
		if signer, err := ssh.ParsePrivateKey(keyFile); err == nil {
			hostKeyCallBack = ssh.FixedHostKey(signer.PublicKey())
			return &hostKeyCallBack
		}
	}

	log.Println("Warning: Failed to load HostKey, using insecure mode.")
	hostKeyCallBack = ssh.InsecureIgnoreHostKey()
	return &hostKeyCallBack
}

//SSHAgent | Obtain all stored keys via SSH_AUTH_SOCK environment variable which stores the SSH agent unix socket.
// func SSHAgent() ssh.AuthMethod {
// 	if sshAgent, err := net.Dial("unix", os.Getenv("SSH_AUTH_SOCK")); err == nil {
// 		return ssh.PublicKeysCallback(agent.NewClient(sshAgent).Signers)
// 	}
// 	return nil
// }
