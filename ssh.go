package sshcommander

import (
	"errors"
	"fmt"
	"io/ioutil"
	"log"
	"regexp"
	"strconv"
	"strings"
	"time"

	"golang.org/x/crypto/ssh"
)

//SSHCommander | SSHCommander
type SSHCommander struct {
	ip              string
	port            int
	user            string
	password        string
	keys            []string
	hostKeyCallback ssh.HostKeyCallback
	output          bool
	signers         []ssh.Signer
	connection      *ssh.Client
}

var matchSudoCommand = regexp.MustCompile(`\bsudo\b\s`)

//NewSSHCommander | Make an new instance of SSHCommander
func NewSSHCommander(sshCommanderOptions *SSHCommanderOptions) (*SSHCommander, error) {
	sshCommander := &SSHCommander{}

	if sshCommanderOptions.SSHHost != nil {
		if sshCommanderOptions.SSHHost.IP == "" {
			return nil, errors.New("Please pass SSHHost.IP")
		}

		if sshCommanderOptions.SSHHost.Port == 0 {
			sshCommanderOptions.SSHHost.Port = 22
		}

		sshCommander.ip = sshCommanderOptions.SSHHost.IP
		sshCommander.port = sshCommanderOptions.SSHHost.Port
	} else {
		return nil, errors.New("Please pass SSHHost option")
	}

	if sshCommanderOptions.SSHCredentials != nil {
		if sshCommanderOptions.SSHCredentials.User == "" {
			return nil, errors.New("Please pass SSHCredentials.User")
		}

		if len(sshCommanderOptions.SSHCredentials.Keys) == 0 && sshCommanderOptions.SSHCredentials.Password == "" {
			return nil, errors.New("Please pass SSHCredentials.Keys or SSHCredentials.Password")
		}

		sshCommander.user = sshCommanderOptions.SSHCredentials.User
		sshCommander.password = sshCommanderOptions.SSHCredentials.Password
		sshCommander.keys = sshCommanderOptions.SSHCredentials.Keys
	} else {
		return nil, errors.New("Please pass SSHCredentials option")
	}

	if sshCommanderOptions.HostKeyCallBack != nil {
		sshCommander.hostKeyCallback = *sshCommanderOptions.HostKeyCallBack
	} else {
		sshCommander.hostKeyCallback = ssh.InsecureIgnoreHostKey()
	}

	sshCommander.output = sshCommanderOptions.Output

	return sshCommander, nil
}

//NewSSHCommand | Make an new instance of SSHCommand
func NewSSHCommand(command string, environments *[]string) *SSHCommand {
	sshCommand := &SSHCommand{
		Cmd: command,
	}

	if environments != nil {
		sshCommand.Env = *environments
	}

	return sshCommand
}

//SetOptions | Change SSHCommander options and reset connection with remote host
func (sshCommander *SSHCommander) SetOptions(sshCommanderOptions *SSHCommanderOptions) error {
	if sshCommanderOptions.SSHHost != nil {
		if sshCommanderOptions.SSHHost.IP != "" {
			sshCommander.ip = sshCommanderOptions.SSHHost.IP
		}

		if sshCommanderOptions.SSHHost.Port != 0 {
			sshCommander.port = sshCommanderOptions.SSHHost.Port
		}
	}

	if sshCommanderOptions.SSHCredentials != nil {
		if sshCommanderOptions.SSHCredentials.User != "" {
			sshCommander.user = sshCommanderOptions.SSHCredentials.User
		}

		if sshCommanderOptions.SSHCredentials.Password != "" {
			sshCommander.password = sshCommanderOptions.SSHCredentials.Password
		}

		if len(sshCommanderOptions.SSHCredentials.Keys) != 0 {
			sshCommander.keys = sshCommanderOptions.SSHCredentials.Keys
		}
	}

	if sshCommanderOptions.HostKeyCallBack != nil {
		sshCommander.hostKeyCallback = *sshCommanderOptions.HostKeyCallBack
	}

	sshCommander.output = sshCommanderOptions.Output

	return sshCommander.Reconnect()
}

//Connect make connection from SSH
func (sshCommander *SSHCommander) Connect() (err error) {
	config := &ssh.ClientConfig{
		User:            sshCommander.user,
		Auth:            []ssh.AuthMethod{},
		HostKeyCallback: sshCommander.hostKeyCallback,
	}

	if len(sshCommander.keys) == 0 {
		config.Auth = append(config.Auth, ssh.Password(sshCommander.password))
	} else {
		if err = sshCommander.loadKeys(); err != nil {
			return
		}
		config.Auth = append(config.Auth, ssh.PublicKeys(sshCommander.signers...))
	}

	if sshCommander.connection, err = ssh.Dial("tcp", fmt.Sprintf("%s:%s", sshCommander.ip, strconv.Itoa(sshCommander.port)), config); err != nil {
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
func (sshCommander *SSHCommander) Reconnect() (err error) {
	if err = sshCommander.Disconnect(); err != nil {
		return
	}

	if err = sshCommander.Connect(); err != nil {
		return
	}

	return
}

//Run | Run an command
func (sshCommander *SSHCommander) Run(sshCommand *SSHCommand) (output string, err error) {
	if sshCommander.connection == nil {
		err = errors.New("Please before run SSHCommander.Connect()")
		return
	}

	if matchSudoCommand.MatchString(sshCommand.Cmd) && sshCommander.password == "" {
		err = errors.New("You cannot execute commands with sudo, pass SSHCredentials.Password for use it")
		return
	}

	if sshCommander.output {
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
		cmd = fmt.Sprintf("sudo -Svp %s; %s", string(sudoPasswordPrompt), cmd)
	}

	if len(sshCommand.Env) > 0 {
		cmd = fmt.Sprintf("%s && %s", strings.Join(sshCommand.Env, " "), cmd)
	}

	if err := session.Start(cmd); err != nil {
		err = fmt.Errorf(ErrRequestShell, err.Error())
	}

	err = session.Wait()
	output = strings.TrimSpace(string(w.b.Bytes()))

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

	sshCommand := NewSSHCommand(command, nil)
	return sshCommander.Run(sshCommand)
}

//RunEnv | Alis for Run
func (sshCommander *SSHCommander) RunEnv(command string, environments []string, args ...interface{}) (string, error) {
	if len(args) > 0 {
		command = fmt.Sprintf(command, args...)
	}

	sshCommand := NewSSHCommand(command, &environments)
	return sshCommander.Run(sshCommand)
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
		fmt.Println("Waiting rebooting remote machine... Retrying in 5s")
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

func (sshCommander *SSHCommander) loadKeys() error {
	if len(sshCommander.signers) == 0 {
		for k := 0; k < len(sshCommander.keys); k++ {
			keyFile, err := ioutil.ReadFile(sshCommander.keys[k])
			if err == nil {
				if signer, err := ssh.ParsePrivateKey(keyFile); err == nil {
					sshCommander.signers = append(sshCommander.signers, signer)
				} else {
					return err
				}
			}
		}
		if len(sshCommander.signers) == 0 {
			return errors.New(ErrKeysNotFound)
		}
	}
	return nil
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
