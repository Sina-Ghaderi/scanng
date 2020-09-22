package main

import (
	"fmt"
	"os"
	"os/exec"
	"regexp"

	"github.com/lxn/walk"
	"github.com/lxn/walk/declarative"
)

// RemoteSSHShell struct type to store ssh data
type RemoteSSHShell struct {
	AuthMthd   int
	HostAddr   string
	HostPort   int
	PreVTKEY   string // private key path
	PassPhrase string
	PassWord   string
	UserName   string
}

func startSSHsession(owner walk.Form, sendipaddr string) (int, error) {
	const regexSingle = `^(([0-9]|[1-9][0-9]|1[0-9]{2}|2[0-4][0-9]|25[0-5])\.){3}([0-9]|[1-9][0-9]|1[0-9]{2}|2[0-4][0-9]|25[0-5])$|^(([a-zA-Z]{1})|([a-zA-Z]{1}[a-zA-Z]{1})|([a-zA-Z]{1}[0-9]{1})|([0-9]{1}[a-zA-Z]{1})|([a-zA-Z0-9][a-zA-Z0-9-_]{1,61}[a-zA-Z0-9]))\.([a-zA-Z]{2,6}|[a-zA-Z0-9-]{2,30}\.[a-zA-Z]{2,3})$`

	var sshClientguiwindow struct {
		dlgSSHAccwin                  *walk.Dialog
		dbindersshx                   *walk.DataBinder
		acceptPB, cancelPB            *walk.PushButton
		mapLineEd, pkLineEd, pKandPHm *walk.LineEdit
		passGBOXm, pKeyGBOXm          *walk.GroupBox
	}

	sshstatset := &RemoteSSHShell{
		AuthMthd: 1,
		HostPort: 22,
		UserName: "root",
		HostAddr: sendipaddr,
	}
	return declarative.Dialog{
		AssignTo:      &sshClientguiwindow.dlgSSHAccwin,
		FixedSize:     true,
		Title:         "SSH Client",
		DefaultButton: &sshClientguiwindow.acceptPB,
		CancelButton:  &sshClientguiwindow.cancelPB,
		DataBinder: declarative.DataBinder{
			AssignTo:       &sshClientguiwindow.dbindersshx,
			Name:           "sshClient",
			DataSource:     sshstatset,
			ErrorPresenter: declarative.ToolTipErrorPresenter{},
		},
		MinSize: declarative.Size{Width: 320, Height: 300},
		Layout:  declarative.VBox{},
		Children: []declarative.Widget{
			declarative.GroupBox{
				Title:  "SSH Client Options",
				Layout: declarative.HBox{},
				Children: []declarative.Widget{
					declarative.Composite{
						Layout: declarative.Grid{Columns: 1},
						Children: []declarative.Widget{
							declarative.GroupBox{
								Title:  "Host Address To Connect",
								Layout: declarative.Grid{Columns: 4},
								Children: []declarative.Widget{
									declarative.LineEdit{
										ToolTipText: "username for ssh connection",
										CueBanner:   "User",
										MaxSize:     declarative.Size{Width: 55},
										Text:        declarative.Bind("UserName"),
									},

									declarative.LineEdit{
										AssignTo:    &sshClientguiwindow.mapLineEd,
										ToolTipText: "format: IP|Domain",
										CueBanner:   "IP or Domain",
										Text:        declarative.Bind("HostAddr"),
									},

									declarative.NumberEdit{
										ToolTipText: "port number",
										MaxSize:     declarative.Size{Width: 40},
										MinSize:     declarative.Size{Width: 40},
										Value:       declarative.Bind("HostPort"),
										MinValue:    1,
										MaxValue:    65535,
									},
								},
							},
							declarative.RadioButtonGroupBox{
								Title:      "Authentication",
								Layout:     declarative.HBox{},
								DataMember: "AuthMthd",
								Buttons: []declarative.RadioButton{
									{MaxSize: declarative.Size{Width: 90}, Text: "Password", Value: 1, OnClicked: func() {
										sshClientguiwindow.passGBOXm.SetVisible(true)
										sshClientguiwindow.pKeyGBOXm.SetVisible(false)
										sshClientguiwindow.pKandPHm.SetVisible(false)
									}},
									{MaxSize: declarative.Size{Width: 90}, Text: "PrivateK", Value: 2, OnClicked: func() {
										sshClientguiwindow.passGBOXm.SetVisible(false)
										sshClientguiwindow.pKeyGBOXm.SetVisible(true)
										sshClientguiwindow.pKandPHm.SetVisible(false)
									}},
									{MaxSize: declarative.Size{Width: 90}, Text: "PK+PasPh", Value: 3, OnClicked: func() {
										sshClientguiwindow.passGBOXm.SetVisible(false)
										sshClientguiwindow.pKeyGBOXm.SetVisible(true)
										sshClientguiwindow.pKandPHm.SetVisible(true)
									}},
								},
							},
							declarative.GroupBox{
								AssignTo: &sshClientguiwindow.passGBOXm,
								Title:    "Login With Password",
								Layout:   declarative.Grid{Columns: 1},
								Children: []declarative.Widget{
									declarative.LineEdit{
										CueBanner:    "Password ...",
										PasswordMode: true,
										Text:         declarative.Bind("PassWord"),
									},
								},
							},
							declarative.GroupBox{
								AssignTo: &sshClientguiwindow.pKeyGBOXm,
								Title:    "Login With Private Key",
								Visible:  false,
								Layout:   declarative.VBox{},
								Children: []declarative.Widget{
									declarative.LineEdit{
										AssignTo:  &sshClientguiwindow.pkLineEd,
										CueBanner: "Private Key File Path ...",
										ReadOnly:  true,
										Text:      declarative.Bind("PreVTKEY"),
									},
									declarative.PushButton{
										Text:        "Open Key File",
										ToolTipText: "open ssh key file",
										OnClicked: func() {
											filePth, err := openPkFile(sshClientguiwindow.dlgSSHAccwin)
											if err != nil {
												walk.MsgBox(sshClientguiwindow.dlgSSHAccwin, "OS file error", fmt.Sprint(err), walk.MsgBoxIconError)
												return
											}
											sshClientguiwindow.pkLineEd.SetText(filePth)
										},
									},
									declarative.LineEdit{
										AssignTo:     &sshClientguiwindow.pKandPHm,
										CueBanner:    "Passphrase for Key ...",
										PasswordMode: true,
										Text:         declarative.Bind("PassPhrase"),
									},
								},
							},
						},
					},
				},
			},
			declarative.Composite{
				Layout: declarative.HBox{},
				Children: []declarative.Widget{
					declarative.HSpacer{},
					declarative.PushButton{
						AssignTo: &sshClientguiwindow.acceptPB,
						Text:     "Connect",
						OnClicked: func() {
							if err := sshClientguiwindow.dbindersshx.Submit(); err != nil {
								return
							}
							if sshstatset.HostAddr == "" {
								sshClientguiwindow.mapLineEd.SetFocus()
								return
							}
							if match, _ := regexp.MatchString(regexSingle, sshstatset.HostAddr); !match {
								walk.MsgBox(sshClientguiwindow.dlgSSHAccwin, "Host syntax error", "Invalid IPv4 or Domain address, format: IPv4|Domain\nExample: slc.snix.ir", walk.MsgBoxIconError)
								return
							}
							if exeErr := exec.Command("cmd", "/c", "start",
								os.Args[0],
								"-auth", fmt.Sprint(sshstatset.AuthMthd),
								"-addr", fmt.Sprintf("%v:%v", sshstatset.HostAddr, sshstatset.HostPort),
								"-user", sshstatset.UserName,
								"-pass", sshstatset.PassWord,
								"-prvk", sshstatset.PreVTKEY,
								"-prph", sshstatset.PassPhrase).Start(); exeErr != nil {
								walk.MsgBox(sshClientguiwindow.dlgSSHAccwin, "Internal System Err", fmt.Sprintf("%v", exeErr), walk.MsgBoxIconError)
								return
							}

						},
					},
					declarative.PushButton{
						AssignTo:  &sshClientguiwindow.cancelPB,
						Text:      "Cancel",
						OnClicked: func() { sshClientguiwindow.dlgSSHAccwin.Cancel() },
					},
				},
			},
		},
	}.Run(owner)
}

func openPkFile(dlgwinad walk.Form) (string, error) {
	openSSHfile := new(walk.FileDialog)
	openSSHfile.Filter = "PEM Files (*.pem)|*.pem|All Files (*.*)|*.*"
	openSSHfile.Title = "Open SSH Key File"
	if okfile, err := openSSHfile.ShowOpen(dlgwinad); err != nil {
		return openSSHfile.FilePath, err
	} else if !okfile {
		return openSSHfile.FilePath, err
	}
	return openSSHfile.FilePath, nil
}
