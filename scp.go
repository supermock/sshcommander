package sshcommander

import (
	"errors"
	"fmt"
	"io"
	"os"
	"path"
	"path/filepath"
	"strconv"
)

//UploadMemoryFile | Copy local memory file to remote machine
func (sshCommander *SSHCommander) UploadMemoryFile(size int64, mode os.FileMode, fileName string, contents io.Reader, destinationPath string) error {
	return sshCommander.copy(size, mode, fileName, contents, destinationPath)
}

//UploadFile | Copy local file to remote machine
func (sshCommander *SSHCommander) UploadFile(localFile, remotePath string) error {
	f, err := os.Open(localFile)
	if err != nil {
		return err
	}
	defer f.Close()
	s, err := f.Stat()
	if err != nil {
		return err
	}
	return sshCommander.copy(s.Size(), s.Mode().Perm(), path.Base(localFile), f, remotePath)
}

//DownloadFile | Copy remote file to local machine
func (sshCommander *SSHCommander) DownloadFile(remoteFile, localPath string) error {
	mode, err := sshCommander.getRemoteFileAccessRights(remoteFile)
	if err != nil {
		return err
	}

	fileName := filepath.Base(remoteFile)
	localFile, err := os.OpenFile(path.Join(localPath, fileName), os.O_CREATE|os.O_RDWR, mode)
	if err != nil {
		return err
	}
	defer localFile.Close()

	session, err := sshCommander.connection.NewSession()
	if err != nil {
		return err
	}
	defer session.Close()

	session.Stdout = localFile

	err = session.Run("/bin/cat " + remoteFile)
	if err != nil {
		return err
	}
	return nil
}

func (sshCommander *SSHCommander) getRemoteFileAccessRights(remoteFile string) (os.FileMode, error) {
	bs, err := sshCommander.Run(NewSSHCommand("/usr/bin/stat --format=%a "+remoteFile, nil))
	if err != nil {
		return 0, err
	}
	mode64, err := strconv.ParseUint(bs, 8, 32)
	if err != nil {
		return 0, err
	}
	return os.FileMode(mode64), nil
}

func (sshCommander *SSHCommander) copy(size int64, mode os.FileMode, fileName string, contents io.Reader, destination string) error {
	if sshCommander.password == "" {
		return errors.New("You cannot use this command without sudo password")
	}

	out, err := sshCommander.Run(NewSSHCommand(fmt.Sprintf("ls %s >/dev/null 2>&1 && echo FOUND || echo NONEFOUND", path.Join("/tmp", fileName)), nil))
	if err != nil {
		return fmt.Errorf("Failed to check if file exists. Err: %s", out)
	}

	if out == "FOUND" {
		if out, err := sshCommander.Run(NewSSHCommand(fmt.Sprintf("rm -rf %s", path.Join("/tmp", fileName)), nil)); err != nil {
			return fmt.Errorf("Failed to delete existing file %s on remote host. Err: %s", fileName, out)
		}
	}

	session, err := sshCommander.connection.NewSession()
	if err != nil {
		return err
	}
	defer session.Close()

	go func() {
		w, _ := session.StdinPipe()
		defer w.Close()
		fmt.Fprintf(w, "C%#o %d %s\n", mode, size, fileName)
		io.Copy(w, contents)
		fmt.Fprint(w, "\x00")
	}()

	if err := session.Run("scp -t /tmp"); err != nil {
		return err
	}

	if destination != "/tmp" {
		if out, err := sshCommander.Run(NewSSHCommand(fmt.Sprintf("sudo mv -f /tmp/%s %s", fileName, destination), nil)); err != nil {
			return fmt.Errorf("Failed on transfer file to destination. Err: %s", out)
		}
	}

	return nil
}
