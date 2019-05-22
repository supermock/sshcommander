package sshcommander

import (
	"errors"
	"fmt"
	"io"
	"os"
	"path"
	"path/filepath"
	"strconv"
	"strings"
)

//UploadFileInMemory | Copy local memory file to remote machine
func (sshCommander *SSHCommander) UploadFileInMemory(size int64, mode os.FileMode, fileName string, contents string, destinationPath string) error {
	return sshCommander.copy(size, mode, fileName, strings.NewReader(contents), destinationPath)
}

//UploadFile | Copy local file to remote machine
func (sshCommander *SSHCommander) UploadFile(localPath, remotePath string) error {
	f, err := os.Open(localPath)
	if err != nil {
		return err
	}
	defer f.Close()

	s, err := f.Stat()
	if err != nil {
		return err
	}

	return sshCommander.copy(s.Size(), s.Mode().Perm(), path.Base(localPath), f, remotePath)
}

//DownloadFile | Copy remote file to local machine
func (sshCommander *SSHCommander) DownloadFile(remotePath, localPath string) error {
	mode, err := sshCommander.readRemoteFileAccessRights(remotePath)
	if err != nil {
		return err
	}

	localFile, err := os.OpenFile(path.Join(localPath, filepath.Base(remotePath)), os.O_CREATE|os.O_RDWR, mode)
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

	return session.Run(fmt.Sprintf("/bin/cat %s", remotePath))
}

func (sshCommander *SSHCommander) readRemoteFileAccessRights(remotePath string) (os.FileMode, error) {
	bs, err := sshCommander.RunCmd("/usr/bin/stat --format=%%a %s", remotePath)
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
	if sshCommander.options.Credentials.Password == "" {
		return errors.New("You cannot use this command without sudo password")
	}

	remotePath := path.Join("/tmp", fileName)

	out, err := sshCommander.RunCmd("ls %s >/dev/null 2>&1 && echo FOUND || echo NONEFOUND", remotePath)
	if err != nil {
		return fmt.Errorf("Failed to check if file exists. Err: %s", out)
	}

	if out == "FOUND" {
		if out, err := sshCommander.RunCmd("rm -f %s", remotePath); err != nil {
			return fmt.Errorf("Failed to delete existing file %s on remote host. Err: %s", remotePath, out)
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
		if out, err := sshCommander.RunCmd("sudo mv -f %s %s", remotePath, destination); err != nil {
			return fmt.Errorf("Failed on transfer file to destination. Err: %s", out)
		}
	}

	return nil
}
