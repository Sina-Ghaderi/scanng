package main

import (
	"fmt"
	"net"
	"regexp"

	"github.com/lxn/walk"
	"github.com/lxn/walk/declarative"
	"github.com/mdlayher/wol"
)

// WakeOnLAN struct type for wake on lan
type WakeOnLAN struct {
	SleepHost, SleepPass, SleepMac string
	SleepPort                      int
}

func runWakeOnLanDg(owner walk.Form, dfgAddr, mactgadd string) (int, error) {
	const regexSingle = "^(([0-9]|[1-9][0-9]|1[0-9]{2}|2[0-4][0-9]|25[0-5])\\.){3}([0-9]|[1-9][0-9]|1[0-9]{2}|2[0-4][0-9]|25[0-5])$"

	var wakeClientguiwindow struct {
		dlgWakeOnLan       *walk.Dialog
		dbindersshx        *walk.DataBinder
		acceptPB, cancelPB *walk.PushButton
		macLine, addrLine  *walk.LineEdit
	}

	wakestatset := &WakeOnLAN{
		SleepHost: dfgAddr,
		SleepMac:  mactgadd,
		SleepPort: 7,
	}
	return declarative.Dialog{
		AssignTo:      &wakeClientguiwindow.dlgWakeOnLan,
		FixedSize:     true,
		Title:         "Wake On LAN Client",
		DefaultButton: &wakeClientguiwindow.acceptPB,
		CancelButton:  &wakeClientguiwindow.cancelPB,
		DataBinder: declarative.DataBinder{
			AssignTo:       &wakeClientguiwindow.dbindersshx,
			Name:           "wakeClient",
			DataSource:     wakestatset,
			ErrorPresenter: declarative.ToolTipErrorPresenter{},
		},
		MinSize: declarative.Size{Width: 320, Height: 300},
		Layout:  declarative.VBox{},
		Children: []declarative.Widget{
			declarative.GroupBox{
				Title:  "Wake On Lan Options",
				Layout: declarative.HBox{},
				Children: []declarative.Widget{
					declarative.Composite{
						Layout: declarative.Grid{Columns: 1},
						Children: []declarative.Widget{
							declarative.GroupBox{
								Title:  "Host Address To Wake",
								Layout: declarative.Grid{Columns: 3},
								Children: []declarative.Widget{
									declarative.LineEdit{
										AssignTo:    &wakeClientguiwindow.addrLine,
										ToolTipText: "format: IP Address",
										CueBanner:   "IPv4 Address...",
										Text:        declarative.Bind("SleepHost"),
									},

									declarative.NumberEdit{
										ToolTipText: "port number",
										MaxSize:     declarative.Size{Width: 40},
										MinSize:     declarative.Size{Width: 40},
										Value:       declarative.Bind("SleepPort"),
										MinValue:    1,
										MaxValue:    65535,
									},
								},
							},
							declarative.GroupBox{
								Title:  "Host MAC Address",
								Layout: declarative.Grid{Columns: 1},
								Children: []declarative.Widget{
									declarative.LineEdit{
										AssignTo:  &wakeClientguiwindow.macLine,
										CueBanner: "Mac Address...",
										Text:      declarative.Bind("SleepMac"),
									},
								},
							},
							declarative.GroupBox{
								Title:  "Optional Wake Up Password",
								Layout: declarative.VBox{},
								Children: []declarative.Widget{
									declarative.LineEdit{
										CueBanner:    "Optional Password...",
										PasswordMode: true,
										Text:         declarative.Bind("SleepPass"),
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
						AssignTo: &wakeClientguiwindow.acceptPB,
						Text:     "Wake Up",
						OnClicked: func() {
							if err := wakeClientguiwindow.dbindersshx.Submit(); err != nil {
								return
							}
							if wakestatset.SleepHost == "" {
								wakeClientguiwindow.addrLine.Focused()
								return
							}
							if wakestatset.SleepMac == "" {
								wakeClientguiwindow.macLine.Focused()
								return
							}
							if match, _ := regexp.MatchString(regexSingle, wakestatset.SleepHost); !match {
								walk.MsgBox(wakeClientguiwindow.dlgWakeOnLan, "Host syntax error", "Invalid IPv4 address, Example: 192.168.1.1", walk.MsgBoxIconError)
								return
							}
							digMacAddr, err := net.ParseMAC(wakestatset.SleepMac)
							if err != nil {
								walk.MsgBox(wakeClientguiwindow.dlgWakeOnLan, "Mac syntax error", fmt.Sprint(err), walk.MsgBoxIconError)
								return
							}
							if err := wakeMachineUp(fmt.Sprintf("%v:%v", wakestatset.SleepHost, wakestatset.SleepPort), digMacAddr, []byte(wakestatset.SleepPass)); err != nil {
								walk.MsgBox(wakeClientguiwindow.dlgWakeOnLan, "Wake on error", fmt.Sprint(err), walk.MsgBoxIconError)
								return
							}
							walk.MsgBox(wakeClientguiwindow.dlgWakeOnLan, "Wake on lan", fmt.Sprintf("sent UDP Wake-on-LAN magic packet using \n%s to %s", wakestatset.SleepHost, wakestatset.SleepMac), walk.MsgBoxIconInformation)
						},
					},
					declarative.PushButton{
						AssignTo:  &wakeClientguiwindow.cancelPB,
						Text:      "Cancel",
						OnClicked: func() { wakeClientguiwindow.dlgWakeOnLan.Cancel() },
					},
				},
			},
		},
	}.Run(owner)
}

func wakeMachineUp(ipaddr string, macaddr net.HardwareAddr, password []byte) error {
	machine, err := wol.NewClient()
	if err != nil {
		return err
	}
	defer machine.Close()
	return machine.WakePassword(ipaddr, macaddr, password)
}
