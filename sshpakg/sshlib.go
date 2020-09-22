package sshpakg

import (
	"bufio"
	"fmt"
	"io/ioutil"
	"net"
	"os"
	"os/signal"
	"syscall"

	"github.com/shiena/ansicolor"
	"golang.org/x/crypto/ssh"
)

// DialWithKey starts a client connection to the given SSH server with key authmethod.
func DialWithKey(addr, user, keyfile string) (*ssh.Client, error) {
	key, err := ioutil.ReadFile(keyfile)
	if err != nil {
		return nil, err
	}

	signer, err := ssh.ParsePrivateKey(key)
	if err != nil {
		return nil, err
	}

	config := &ssh.ClientConfig{
		User: user,
		Auth: []ssh.AuthMethod{
			ssh.PublicKeys(signer),
		},
		HostKeyCallback: ssh.HostKeyCallback(func(hostname string, remote net.Addr, key ssh.PublicKey) error { return nil }),
	}

	return ssh.Dial("tcp", addr, config)
}

// DialWithKeyWithPassphrase same as DialWithKey but with a passphrase to decrypt the private key
func DialWithKeyWithPassphrase(addr, user, keyfile string, passphrase string) (*ssh.Client, error) {
	key, err := ioutil.ReadFile(keyfile)
	if err != nil {
		return nil, err
	}

	signer, err := ssh.ParsePrivateKeyWithPassphrase(key, []byte(passphrase))
	if err != nil {
		return nil, err
	}

	config := &ssh.ClientConfig{
		User: user,
		Auth: []ssh.AuthMethod{
			ssh.PublicKeys(signer),
		},
		HostKeyCallback: ssh.HostKeyCallback(func(hostname string, remote net.Addr, key ssh.PublicKey) error { return nil }),
	}

	return ssh.Dial("tcp", addr, config)
}

// DialWithPasswd starts a client connection to the given SSH server with passwd authmethod.
func DialWithPasswd(addr, user, passwd string) (*ssh.Client, error) {
	config := &ssh.ClientConfig{
		User: user,
		Auth: []ssh.AuthMethod{
			ssh.Password(passwd),
		},
		HostKeyCallback: ssh.HostKeyCallback(func(hostname string, remote net.Addr, key ssh.PublicKey) error { return nil }),
	}

	return ssh.Dial("tcp", addr, config)
}

// InitSSHSession initial an ssh session
func InitSSHSession(conn *ssh.Client) error {
	session, err := conn.NewSession()
	if err != nil {
		return err
	}
	defer session.Close()
	session.Stdout = ansicolor.NewAnsiColorWriter(os.Stdout)
	session.Stderr = ansicolor.NewAnsiColorWriter(os.Stderr)
	sysinput, _ := session.StdinPipe()

	if err := session.RequestPty("vt100", 80, 40, ssh.TerminalModes{
		ssh.ECHO:          0,
		ssh.IGNCR:         1,
		ssh.ECHOCTL:       0,
		ssh.TTY_OP_ISPEED: 14400,
		ssh.TTY_OP_OSPEED: 14400,
	}); err != nil {
		return err
	}
	if err := session.Shell(); err != nil {
		return err
	}
	ctrlC := make(chan os.Signal, 1)
	signal.Notify(ctrlC, syscall.SIGINT)
	go func() {
		for {
			<-ctrlC
			fmt.Println("^C")
			// for some reason OpenSSH dose not support Signal method, so ...
			// i have to do this in old school way
			sysinput.Write([]byte("\x03"))
		}
	}()
	go func() {
		for {
			inputReader := bufio.NewReader(os.Stdin)

			str, _ := inputReader.ReadString('\n')
			fmt.Fprint(sysinput, str)
		}
	}()
	// exit ...
	if err := session.Wait(); err != nil {
		if e, ok := err.(*ssh.ExitError); ok {
			switch e.ExitStatus() {
			case 130:
				return nil
			}
		}
		return err
	}
	return nil
}
