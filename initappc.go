package main

import (
	"flag"
	"fmt"
	"gopher-scan/sshpakg"
	"os"

	"github.com/lxn/walk"
	"github.com/lxn/walk/declarative"
)

func main() {
	if len(os.Args) <= 1 {
		startMainGUIWindows()
		return
	}
	// So ... seems walk package dose not support console windows,
	// obviously this is not the best way to call another console for ssh client
	// but this is the only way that i could think of ... let me know if you find better way to do this.
	sshCodeAuth := flag.String("auth", "1", "ssh auth type")
	sshHostAddr := flag.String("addr", "127.0.0.1:22", "ssh remote host")
	sshUserName := flag.String("user", "root", "ssh username")
	sshPassWord := flag.String("pass", "toor", "ssh password")
	sshPrivateK := flag.String("prvk", "pkey.pem", "ssh private key")
	sshPkPassPH := flag.String("prph", "123", "ssh key passphrase")
	flag.Parse()
	var winSSHcli *walk.MainWindow
	sshExecute := declarative.MainWindow{
		AssignTo: &winSSHcli,
		Visible:  false,
	}
	go sshExecute.Run()
	switch *sshCodeAuth {
	case "1":
		conn, err := sshpakg.DialWithPasswd(*sshHostAddr, *sshUserName, *sshPassWord)
		if err != nil {
			walk.MsgBox(winSSHcli, "Connection error", fmt.Sprintf("%v", err), walk.MsgBoxIconError)
			return
		}
		if err := sshpakg.InitSSHSession(conn); err != nil {
			walk.MsgBox(winSSHcli, "Connection error", fmt.Sprintf("%v", err), walk.MsgBoxIconError)
			return
		}
	case "2":
		conn, err := sshpakg.DialWithKey(*sshHostAddr, *sshUserName, *sshPrivateK)
		if err != nil {
			walk.MsgBox(winSSHcli, "Connection error", fmt.Sprintf("%v", err), walk.MsgBoxIconError)
			return
		}
		if err := sshpakg.InitSSHSession(conn); err != nil {
			walk.MsgBox(winSSHcli, "Connection error", fmt.Sprintf("%v", err), walk.MsgBoxIconError)
			return
		}
	case "3":
		conn, err := sshpakg.DialWithKeyWithPassphrase(*sshHostAddr, *sshUserName, *sshPrivateK, *sshPkPassPH)
		if err != nil {
			walk.MsgBox(winSSHcli, "Connection error", fmt.Sprintf("%v", err), walk.MsgBoxIconError)
			return
		}
		if err := sshpakg.InitSSHSession(conn); err != nil {
			walk.MsgBox(winSSHcli, "Connection error", fmt.Sprintf("%v", err), walk.MsgBoxIconError)
			return
		}
	}
}
