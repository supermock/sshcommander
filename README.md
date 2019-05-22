# sshcommander (WIP)
Package that provides more options when connecting with ssh via golang

Simple usage example:

```go
package main

import (
	"log"

	"github.com/supermock/sshcommander"
)

func main() {
	term, _ := sshcommander.NewSSHCommander(&sshcommander.Options{
		Host: &sshcommander.Host{
			IP:   "localhost",
			Port: 22,
		},
		Credentials: &sshcommander.Credentials{
			User:     "your-user",
			Password: "******",
		},
		Output: true,
	})

	if err := term.Connect(); err != nil {
		log.Fatal(err)
	}
	defer term.Disconnect()

	if out, err := term.RunCmd("cat /etc/issue"); err != nil {
		log.Fatalf("Failed on execute command. Err: %s", err)
	} else {
		log.Println(out)
	}

	if out, err := term.RunCmd("sudo ip addr"); err != nil {
		log.Fatalf("Failed on execute command. Err: %s", err)
	} else {
		log.Println(out)
	}
}
```
