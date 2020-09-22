package main

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/csv"
	"fmt"
	"gopher-scan/ifconfig"
	"gopher-scan/scream"
	"image/png"
	"net"
	"os"
	"os/exec"
	"regexp"
	"runtime"
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/lxn/walk"
	"github.com/lxn/walk/declarative"
	"github.com/lxn/win"
	"golang.org/x/sys/windows"
)

const regexRange string = "^(([0-9]|[1-9][0-9]|1[0-9]{2}|2[0-4][0-9]|25[0-5])\\.){3}([0-9]|[1-9][0-9]|1[0-9]{2}|2[0-4][0-9]|25[0-5])(\\/([0-9]|[1-2][0-9]|3[0-2]))$"

// HostStruct data type
type HostStruct struct {
	Mac     string
	Cip     string
	Opt     string
	Ven     string
	Let     string
	Inf     string
	checked bool
}

var exdata [][]string
var mdata *VModel
var imdone = make(chan int8, 32)
var serachIndexCache serachIndexCacheType

// VModel struct to show data in gui windows
type VModel struct {
	walk.TableModelBase
	walk.SorterBase
	sortColumn int
	sortOrder  walk.SortOrder
	items      []*HostStruct
}
type serachIndexCacheType struct {
	search string
	indexs []int
	showit int64
}

// SerIPscan ... struct for ipscanner settings
type SerIPscan struct {
	GreenThreads, Ptime                    int
	Pscan1, Pscan2, Pscan3, Pscan4, Pscan5 scream.PortType
	SysIPrange                             []string
	NetBs, Pong, PscanTOF                  bool
}

var cachedSystemIconsForWidthAndDllIdx = make(map[widthAndDllIdx]*walk.Icon)

type widthAndDllIdx struct {
	width int
	idx   int32
	dll   string
}

var globalmaingui struct {
	pushBTS, pushDadd, pushSet, pushPause *walk.PushButton
	mainwindowsUI                         *walk.MainWindow
	statShowBox                           *walk.LineEdit
	lineEdite, srchBox                    *walk.LineEdit
	ipTB                                  *walk.TableView
	saveCSV, saveTXT, mapperAC            *walk.Action
	progsBar                              *walk.ProgressBar
	apipAdd, stSp, pScan                  bool
}

func startMainGUIWindows() {
	const (
		mwsizew = 865
		mwsizeh = 500
	)
	walk.AppendToWalkInit(func() {
		walk.InteractionEffect, _ = walk.NewDropShadowEffect(walk.RGB(63, 63, 63))
		walk.ValidationErrorEffect, _ = walk.NewBorderGlowEffect(walk.RGB(255, 0, 0))

	})
	// default setting
	settings := &SerIPscan{GreenThreads: 32,
		Pscan1:     scream.PortType{Nm: 80, Tp: "TCP"},
		Pscan2:     scream.PortType{Nm: 443, Tp: "TCP"},
		Pscan3:     scream.PortType{Nm: 22, Tp: "TCP"},
		Pscan4:     scream.PortType{Nm: 3389, Tp: "TCP"},
		Pscan5:     scream.PortType{Nm: 445, Tp: "TCP"},
		SysIPrange: ifconfig.Getsysrange(false),
		PscanTOF:   true,
		Ptime:      1,
		NetBs:      true,
		Pong:       true,
	}

	declarative.MainWindow{
		AssignTo: &globalmaingui.mainwindowsUI,
		Visible:  false,
		Title:    "Gopher IP Scan",
		Layout:   declarative.VBox{},
		MenuItems: []declarative.MenuItem{
			declarative.Menu{
				Text: "&File",
				Items: []declarative.MenuItem{
					declarative.Action{
						AssignTo: &globalmaingui.saveCSV,
						Text:     "Save in CSV",
						Image:    loadSystemIcon("shell32", 69, 16),
						OnTriggered: func() {
							if len(exdata) == 0 {
								walk.MsgBox(globalmaingui.mainwindowsUI, "Empty ip scan table", "please start scan to fill the table ...\nthen try to save data in a file", walk.MsgBoxIconInformation)
								return
							}
							fdlg := new(walk.FileDialog)
							fdlg.Title = "Save To CSV File"
							fdlg.Filter = "Comma-separated values file (*.csv)"
							if ok, _ := fdlg.ShowSave(globalmaingui.mainwindowsUI); !ok {
								return
							}
							if !strings.HasSuffix(fdlg.FilePath, ".csv") {
								fdlg.FilePath += ".csv"
							}

							saveInCSV(createosfile(fdlg.FilePath))
						},
					},
					declarative.Action{
						AssignTo: &globalmaingui.saveTXT,
						Text:     "Save in TXT",
						Image:    loadSystemIcon("shell32", 258, 16),
						OnTriggered: func() {
							if len(exdata) == 0 {
								walk.MsgBox(globalmaingui.mainwindowsUI, "Empty ip scan table", "please start scan to fill the table ...\nthen try to save data in a file", walk.MsgBoxIconInformation)
								return
							}
							fdlg := new(walk.FileDialog)
							fdlg.Title = "Save To TXT File"
							fdlg.Filter = "Text file (*.txt)"
							if ok, _ := fdlg.ShowSave(globalmaingui.mainwindowsUI); !ok {
								return
							}
							if !strings.HasSuffix(fdlg.FilePath, ".txt") {
								fdlg.FilePath += ".txt"
							}

							saveInTXT(createosfile(fdlg.FilePath))
						},
					},
					declarative.Separator{},
					declarative.Action{
						Text:        "Exit (Alt+F4)",
						OnTriggered: func() { globalmaingui.mainwindowsUI.Close() },
						Image:       loadSystemIcon("netshell", 98, 16),
					},
				},
			},
			declarative.Menu{
				Text: "&Tools",
				Items: []declarative.MenuItem{
					declarative.Action{
						AssignTo: &globalmaingui.mapperAC,
						Text:     "Port Mapper",
						OnTriggered: func() {
							runMapperDlg(globalmaingui.mainwindowsUI, "")
						},
						Image: loadSystemIcon("shell32", 22, 16),
					},
					declarative.Action{
						Text: "Remote SSH",
						OnTriggered: func() {
							startSSHsession(globalmaingui.mainwindowsUI, "")
						},
						Image: loadSystemIcon("shell32", 24, 16),
					},
					declarative.Action{
						Text: "Wake On LAN",
						OnTriggered: func() {
							runWakeOnLanDg(globalmaingui.mainwindowsUI, "", "")
						},
						Image: loadSystemIcon("imageres", 96, 16),
					},
				},
			},
			declarative.Menu{
				Text: "&Help",
				Items: []declarative.MenuItem{
					declarative.Action{
						Text:  "GitHub Page",
						Image: loadSystemIcon("shell32", 242, 16),
						OnTriggered: func() {
							win.ShellExecute(globalmaingui.mainwindowsUI.Handle(), nil, windows.StringToUTF16Ptr("https://github.com/sina-ghaderi/gopher-scan"), nil, nil, win.SW_SHOWNORMAL)
						},
					},
					declarative.Action{
						Text:  "Report a Bug",
						Image: loadSystemIcon("shell32", 242, 16),
						OnTriggered: func() {
							win.ShellExecute(globalmaingui.mainwindowsUI.Handle(), nil, windows.StringToUTF16Ptr("https://github.com/Sina-Ghaderi/gopher-scan/issues/new"), nil, nil, win.SW_SHOWNORMAL)
						},
					},
					declarative.Action{
						Text:  "About GIPS...",
						Image: loadSystemIcon("shell32", 277, 16),
						OnTriggered: func() {
							runAboutDialog(globalmaingui.mainwindowsUI)
						},
					},
				},
			},
		},
		Children: []declarative.Widget{
			declarative.GroupBox{
				Title:  "IP Scanner Actions",
				Layout: declarative.Grid{Columns: 4},
				Children: []declarative.Widget{
					declarative.PushButton{
						AssignTo:    &globalmaingui.pushBTS,
						MaxSize:     declarative.Size{Width: 100},
						Text:        " Start Scan",
						Image:       loadSystemIcon("shell32", 137, 22),
						ToolTipText: "Start/Stop Scan",
						OnClicked: func() {
							if !globalmaingui.stSp {
								for _, i := range strings.Split(globalmaingui.lineEdite.Text(), ",") {
									if len(globalmaingui.lineEdite.Text()) == 0 {
										globalmaingui.lineEdite.SetFocus()
										return
									}
									if match, _ := regexp.MatchString(regexRange, i); !match {
										walk.MsgBox(globalmaingui.mainwindowsUI, "IP syntax error", "Invalid IPv4 address, format: IPv4/cidr,IPv4/cidr...\nExample: 192.168.1.0/24,172.16.0.0/16", walk.MsgBoxIconError)
										return
									}
								}
								settings.SysIPrange = ifconfig.RemoveDuplicates(strings.Split(globalmaingui.lineEdite.Text(), ","))
								globalmaingui.stSp = true
								mdata = new(VModel)
								globalmaingui.ipTB.SetModel(mdata)
								go scanstat(settings.SysIPrange)
								go settings.winscream()
								globalmaingui.pushBTS.SetText(" Stop Scan")
								globalmaingui.pushBTS.SetImage(loadSystemIcon("comres", 10, 22))
								globalmaingui.progsBar.SetVisible(true)
								globalmaingui.statShowBox.SetVisible(true)
								globalmaingui.pushDadd.SetEnabled(false)
								globalmaingui.pushSet.SetEnabled(false)
								globalmaingui.pushPause.SetEnabled(true)
								globalmaingui.saveCSV.SetEnabled(false)
								globalmaingui.saveTXT.SetEnabled(false)
								globalmaingui.mapperAC.SetEnabled(false)
								globalmaingui.lineEdite.SetReadOnly(true)
								globalmaingui.srchBox.SetReadOnly(true)
								globalmaingui.srchBox.SetText("Search in Result...")
								serachIndexCache = serachIndexCacheType{}
							} else {
								globalmaingui.pushBTS.SetEnabled(false)
								globalmaingui.pushPause.SetEnabled(false)
								scream.StopChan <- struct{}{}
							}
						},
					},

					declarative.PushButton{
						AssignTo:    &globalmaingui.pushPause,
						Enabled:     false,
						Image:       loadSystemIcon("comres", 5, 22),
						MaxSize:     declarative.Size{Width: 100},
						Text:        " Pause Scan",
						ToolTipText: "Pause runing scan",
						OnClicked: func() {
							if !globalmaingui.pScan {
								globalmaingui.pushPause.SetEnabled(false)
								scream.PauseChan <- struct{}{}
								time.Sleep(time.Second) // too much click
								globalmaingui.pushPause.SetText(" Continue")
								globalmaingui.pScan = true
								globalmaingui.pushPause.SetEnabled(true)
							} else {
								globalmaingui.pushPause.SetEnabled(false)
								scream.ContChan <- struct{}{}
								time.Sleep(time.Second) // ...
								globalmaingui.pushPause.SetText(" Puase Scan")
								globalmaingui.pScan = false
								globalmaingui.pushPause.SetEnabled(true)
							}
						},
					},
					declarative.PushButton{
						AssignTo:    &globalmaingui.pushSet,
						MaxSize:     declarative.Size{Width: 100},
						Image:       loadSystemIcon("dsuiext", 35, 22),
						Text:        " Edit Settings",
						ToolTipText: "Show IP scan settings",
						OnClicked: func() {
							runSettingsDG(globalmaingui.mainwindowsUI, settings)
						},
					},
					declarative.PushButton{
						AssignTo:    &globalmaingui.pushDadd,
						MaxSize:     declarative.Size{Width: 100},
						Image:       loadSystemIcon("shell32", 164, 22),
						Text:        " IP Range",
						ToolTipText: "Also scan Apipa and ... default addresses",
						OnClicked: func() {
							if !globalmaingui.apipAdd {
								settings.SysIPrange = ifconfig.Getsysrange(true)
								globalmaingui.lineEdite.SetText(fancyiprange(settings.SysIPrange))
								globalmaingui.apipAdd = true
								globalmaingui.pushDadd.SetText(" Del IP Range")
								return
							}
							settings.SysIPrange = ifconfig.Getsysrange(false)
							globalmaingui.lineEdite.SetText(fancyiprange(settings.SysIPrange))
							globalmaingui.apipAdd = false
							globalmaingui.pushDadd.SetText(" IP Range")
						},
					},
				},
			},
			declarative.GroupBox{
				Title:  "IPv4 Range To Scan",
				Layout: declarative.Grid{Columns: 2},
				Children: []declarative.Widget{
					declarative.LineEdit{
						AssignTo:    &globalmaingui.lineEdite,
						Text:        fancyiprange(settings.SysIPrange),
						ToolTipText: "format: IPv4/cidr,IPv4/cidr,IPv4/cidr...",
						CueBanner:   "IPv4/cidr Network To Scan ... Example: 172.16.0.0/16,192.168.1.0/24,10.0.0.0/8",
					},
					declarative.LineEdit{
						AssignTo:    &globalmaingui.srchBox,
						CueBanner:   "Search in Result...",
						ToolTipText: "press enter to find next",
						MaxSize:     declarative.Size{Width: 180},
						OnKeyPress: func(key walk.Key) {
							if key == walk.KeyReturn {
								if len(globalmaingui.srchBox.Text()) == 0 {
									return
								}
								rows := searchGrep(globalmaingui.srchBox.Text())
								if len(rows) == 0 {
									return
								}
								if int(serachIndexCache.showit) == len(serachIndexCache.indexs) {
									serachIndexCache.showit = 0
								}
								globalmaingui.ipTB.SetCurrentIndex(serachIndexCache.indexs[serachIndexCache.showit])
								serachIndexCache.showit++
							}
						},
					},
				},
			},
			declarative.GroupBox{
				Title:  "Scan Result Table",
				Layout: declarative.Grid{Columns: 1},
				Children: []declarative.Widget{
					declarative.TableView{
						AssignTo:           &globalmaingui.ipTB,
						AlternatingRowBG:   false,
						ColumnsOrderable:   true,
						CustomHeaderHeight: 21,
						CustomRowHeight:    19,
						Columns: []declarative.TableViewColumn{
							{Title: "IP Address", Name: "Cip", Width: 110},
							{Title: "Mac Address", Name: "Mac", Width: 110},
							{Title: "Latency", Name: "Len", Width: 75},
							{Title: "Manufacture", Name: "Ven", Width: 175},
							{Title: "Open Ports", Name: "Opt", Width: 175, Format: "%v"},
							{Title: "Additional Info", Name: "Inf", Width: 163, Format: "%v"},
						},
					},
					declarative.ProgressBar{
						AssignTo:    &globalmaingui.progsBar,
						MinValue:    0,
						MaxValue:    100,
						ToolTipText: "Progress Bar",
						MaxSize:     declarative.Size{Height: 19},
						Visible:     false,
					},

					declarative.LineEdit{
						AssignTo: &globalmaingui.statShowBox,
						Visible:  false,
						ReadOnly: true,
					},
				},
			},
		},
	}.Create()
	defaultStyle := win.GetWindowLong(globalmaingui.mainwindowsUI.Handle(), win.GWL_STYLE)
	newStyle := defaultStyle &^ win.WS_THICKFRAME
	win.SetWindowLong(globalmaingui.mainwindowsUI.Handle(), win.GWL_STYLE, newStyle)

	xScreen := win.GetSystemMetrics(win.SM_CXSCREEN)
	yScreen := win.GetSystemMetrics(win.SM_CYSCREEN)
	win.SetWindowPos(
		globalmaingui.mainwindowsUI.Handle(),
		0,
		(xScreen-mwsizew)/2,
		(yScreen-mwsizeh)/2,
		mwsizew,
		mwsizeh,
		win.SWP_FRAMECHANGED,
	)
	win.ShowWindow(globalmaingui.mainwindowsUI.Handle(), win.SW_SHOW)

	contextMenu, _ := walk.NewMenu()
	globalmaingui.ipTB.AddDisposable(contextMenu)
	pingAction := walk.NewAction()
	pingAction.SetText("Ping Address")
	pingAction.SetImage(loadSystemIcon("shell32", 167, 16))
	pingAction.Triggered().Attach(func() {
		if globalmaingui.ipTB.CurrentIndex() < 0 {
			walk.MsgBox(globalmaingui.mainwindowsUI, "Scan Is Runing", "ip scan is runing right now, please try this when scan is finished", walk.MsgBoxIconInformation)
			return
		}
		if exeErr := exec.Command("cmd", "/c", "start", "ping", mdata.items[globalmaingui.ipTB.CurrentIndex()].Cip, "-t").Start(); exeErr != nil {
			walk.MsgBox(globalmaingui.mainwindowsUI, "Internal System Err", fmt.Sprintf("%v", exeErr), walk.MsgBoxIconError)
			return
		}
	})
	contextMenu.Actions().Add(pingAction)
	mstscAction := walk.NewAction()
	mstscAction.SetText("Remote Desktop")
	mstscAction.SetImage(loadSystemIcon("mstscax", 0, 16))
	mstscAction.Triggered().Attach(func() {
		if globalmaingui.ipTB.CurrentIndex() < 0 {
			walk.MsgBox(globalmaingui.mainwindowsUI, "Scan Is Runing", "ip scan is runing right now, please try this when scan is finished", walk.MsgBoxIconInformation)
			return
		}
		if exeErr := exec.Command("mstsc", "/v", mdata.items[globalmaingui.ipTB.CurrentIndex()].Cip).Start(); exeErr != nil {
			walk.MsgBox(globalmaingui.mainwindowsUI, "Internal System Err", fmt.Sprintf("%v", exeErr), walk.MsgBoxIconError)
			return
		}
	})
	contextMenu.Actions().Add(mstscAction)
	browseAction := walk.NewAction()
	browseAction.SetText("Open in Browser")
	browseAction.SetImage(loadSystemIcon("shell32", 242, 16))
	browseAction.Triggered().Attach(func() {
		if globalmaingui.ipTB.CurrentIndex() < 0 {
			walk.MsgBox(globalmaingui.mainwindowsUI, "Scan Is Runing", "ip scan is runing right now, please try this when scan is finished", walk.MsgBoxIconInformation)
			return
		}
		win.ShellExecute(globalmaingui.mainwindowsUI.Handle(), nil, windows.StringToUTF16Ptr("http://"+mdata.items[globalmaingui.ipTB.CurrentIndex()].Cip), nil, nil, win.SW_SHOWNORMAL)
	})
	contextMenu.Actions().Add(browseAction)

	//
	traceAction := walk.NewAction()
	traceAction.SetText("Trace Address")
	traceAction.SetImage(loadSystemIcon("shell32", 18, 16))
	traceAction.Triggered().Attach(func() {
		if globalmaingui.ipTB.CurrentIndex() < 0 {
			walk.MsgBox(globalmaingui.mainwindowsUI, "Scan Is Runing", "ip scan is runing right now, please try this when scan is finished", walk.MsgBoxIconInformation)
			return
		}
		if exeErr := exec.Command("cmd", "/c", "start", "tracert", mdata.items[globalmaingui.ipTB.CurrentIndex()].Cip).Start(); exeErr != nil {
			walk.MsgBox(globalmaingui.mainwindowsUI, "Internal System Err", fmt.Sprintf("%v", exeErr), walk.MsgBoxIconError)
			return
		}
	})
	contextMenu.Actions().Add(traceAction)
	ftpAction := walk.NewAction()
	ftpAction.SetText("FTP File Share")
	ftpAction.SetImage(loadSystemIcon("shell32", 164, 16))
	ftpAction.Triggered().Attach(func() {
		if globalmaingui.ipTB.CurrentIndex() < 0 {
			walk.MsgBox(globalmaingui.mainwindowsUI, "Scan Is Runing", "ip scan is runing right now, please try this when scan is finished", walk.MsgBoxIconInformation)
			return
		}
		if exeErr := exec.Command("cmd", "/c", `%windir%\explorer`, "ftp://"+mdata.items[globalmaingui.ipTB.CurrentIndex()].Cip).Start(); exeErr != nil {
			walk.MsgBox(globalmaingui.mainwindowsUI, "Internal System Err", fmt.Sprintf("%v", exeErr), walk.MsgBoxIconError)
			return
		}
	})
	contextMenu.Actions().Add(ftpAction)
	smbAction := walk.NewAction()
	smbAction.SetText("SMB File Share")
	smbAction.SetImage(loadSystemIcon("imageres", 137, 16))
	smbAction.Triggered().Attach(func() {
		if globalmaingui.ipTB.CurrentIndex() < 0 {
			walk.MsgBox(globalmaingui.mainwindowsUI, "Scan Is Runing", "ip scan is runing right now, please try this when scan is finished", walk.MsgBoxIconInformation)
			return
		}
		if exeErr := exec.Command("cmd", "/c", `%windir%\explorer`, `\\`+mdata.items[globalmaingui.ipTB.CurrentIndex()].Cip+`\`).Start(); exeErr != nil {
			walk.MsgBox(globalmaingui.mainwindowsUI, "Internal System Err", fmt.Sprintf("%v", exeErr), walk.MsgBoxIconError)
			return
		}
	})
	contextMenu.Actions().Add(smbAction)
	sshdAction := walk.NewAction()
	sshdAction.SetText("Remote SSH")
	sshdAction.SetImage(loadSystemIcon("shell32", 24, 16))
	sshdAction.Triggered().Attach(func() {
		if globalmaingui.ipTB.CurrentIndex() < 0 {
			walk.MsgBox(globalmaingui.mainwindowsUI, "Scan Is Runing", "ip scan is runing right now, please try this when scan is finished", walk.MsgBoxIconInformation)
			return
		}
		startSSHsession(globalmaingui.mainwindowsUI, mdata.items[globalmaingui.ipTB.CurrentIndex()].Cip)
	})
	contextMenu.Actions().Add(sshdAction)
	mapAction := walk.NewAction()
	mapAction.SetText("Run Port Mapper")
	mapAction.SetImage(loadSystemIcon("shell32", 22, 16))
	mapAction.Triggered().Attach(func() {
		if globalmaingui.ipTB.CurrentIndex() < 0 {
			walk.MsgBox(globalmaingui.mainwindowsUI, "Scan Is Runing", "ip scan is runing right now, please try this when scan is finished", walk.MsgBoxIconInformation)
			return
		}
		if !globalmaingui.mapperAC.Enabled() {
			walk.MsgBox(globalmaingui.mainwindowsUI, "Scan Is Runing", "ip scan is runing right now, please try this when scan is finished", walk.MsgBoxIconInformation)
			return
		}
		runMapperDlg(globalmaingui.mainwindowsUI, mdata.items[globalmaingui.ipTB.CurrentIndex()].Cip)
	})
	contextMenu.Actions().Add(mapAction)
	wakeAction := walk.NewAction()
	wakeAction.SetText("Wake On LAN")
	wakeAction.SetImage(loadSystemIcon("imageres", 96, 16))
	wakeAction.Triggered().Attach(func() {
		if globalmaingui.ipTB.CurrentIndex() < 0 {
			walk.MsgBox(globalmaingui.mainwindowsUI, "Scan Is Runing", "ip scan is runing right now, please try this when scan is finished", walk.MsgBoxIconInformation)
			return
		}
		runWakeOnLanDg(globalmaingui.mainwindowsUI, mdata.items[globalmaingui.ipTB.CurrentIndex()].Cip, mdata.items[globalmaingui.ipTB.CurrentIndex()].Mac)
	})
	contextMenu.Actions().Add(wakeAction)

	globalmaingui.ipTB.SetContextMenu(contextMenu)
	globalmaingui.ipTB.SetGridlines(true)
	globalmaingui.mainwindowsUI.Run()
}

func fancyiprange(str []string) (nets string) {
	for _, j := range str {
		nets = fmt.Sprint(nets + j + ",")
	}
	if len(nets) > 0 {
		nets = nets[:len(nets)-1]
	}
	return nets
}

func (p *SerIPscan) winscream() {
	slclockmres := sync.Mutex{}
	dummg := sync.WaitGroup{}
	semap := scream.NewWeighted(int64(p.GreenThreads))
	defer func() {
		// Pack it up boys... we're done here
		dummg.Wait()
		globalmaingui.pushBTS.SetText(" Start Scan")
		globalmaingui.pushBTS.SetImage(loadSystemIcon("shell32", 137, 22))
		globalmaingui.pushPause.SetText(" Pause Scan")
		globalmaingui.pushBTS.SetEnabled(true)
		globalmaingui.pushDadd.SetEnabled(true)
		globalmaingui.pushSet.SetEnabled(true)
		globalmaingui.pushPause.SetEnabled(false)
		globalmaingui.lineEdite.SetReadOnly(false)
		globalmaingui.progsBar.SetVisible(false)
		globalmaingui.statShowBox.SetVisible(false)
		globalmaingui.saveCSV.SetEnabled(true)
		globalmaingui.saveTXT.SetEnabled(true)
		globalmaingui.mapperAC.SetEnabled(true)
		globalmaingui.srchBox.SetReadOnly(false)
		globalmaingui.srchBox.SetText("")
		globalmaingui.stSp, globalmaingui.pScan = false, false
		imdone <- 1
	}()
	startDomino := func(ipn string) {
		defer semap.Release(1)
		defer dummg.Done()
		ip := net.ParseIP(ipn).To4()
		fmc, err := scream.SendARP(ip)
		if err == nil {
			m := &HostStruct{Cip: ipn, Mac: fmc.String()}
			iden, isthere := macven[strings.ToUpper(strings.Replace(fmc.String(), ":", "", -1)[0:6])]
			if !p.NetBs {
				m.Ven = "[N/A]"
			} else if isthere {
				m.Ven = iden
			} else {
				m.Ven = "Unknow Manufacture"
			}
			if p.PscanTOF {
				for _, i := range scream.StartPscan(ipn, time.Duration(1*time.Second), 3, p.Pscan1, p.Pscan2, p.Pscan3, p.Pscan4, p.Pscan5) {
					if i.Stat == "open" {
						m.Opt += fmt.Sprintf("%v %v ", i.Number, strings.ToUpper(i.Ptype))
						if websig, err := scream.DetectWeb(ipn, i.Number); err == nil {
							m.Inf += fmt.Sprintf("%v (http --> %v) ", i.Number, websig)
						}
					}
				}
			}
			if len(m.Opt) == 0 {
				m.Opt = "[N/A]"
			}
			if len(m.Inf) == 0 {
				m.Inf = "[N/A]"
			}
			if p.Pong {
				_, reptime, err := scream.PingHost(ipn, p.Ptime)
				if err != nil {
					m.Let = "TimeOut"
				} else {
					m.Let = reptime.String()
				}
			} else {
				m.Let = "[N/A]"
			}
			slclockmres.Lock()
			mdata.items = append(mdata.items, m)
			exdata = append(exdata, []string{m.Cip, m.Mac, m.Let, m.Ven, m.Opt, m.Inf})
			mdata.PublishRowsReset()
			globalmaingui.ipTB.EnsureItemVisible(len(mdata.items) - 1)
			slclockmres.Unlock()
		}
		imdone <- 0
	}

	for _, iprange := range p.SysIPrange {
		hosts, _ := scream.GetHosts(iprange)
		for _, i := range hosts {
			if signal, _ := semap.AcquireSnix(context.TODO(), 1); signal != 0 {
				// oops!
				return
			}
			dummg.Add(1)
			go startDomino(i)
		}
		dummg.Wait()
	}
}

func scanstat(allranges []string) {
	var tasks, jobdn int
	for _, iprange := range allranges {
		hosts, _ := scream.GetHosts(iprange)
		tasks += len(hosts)
	}

	for {
		if cc, _ := <-imdone; cc == 0 {
			jobdn++
			prcstatus := 100 - (float64(tasks-jobdn)/float64(tasks))*float64(100)
			globalmaingui.progsBar.SetValue(int(prcstatus))
			globalmaingui.statShowBox.SetText(fmt.Sprintf("Progress: %.2f%%\t\tTotal: %v\t\tChecked: %v\t\tAlive: %v", prcstatus, tasks, jobdn, len(mdata.items)))

		} else {
			globalmaingui.progsBar.SetValue(0)
			globalmaingui.statShowBox.SetText("Progress: 0\t\tTotal: 0\t\tChecked: 0\t\tAlive: 0")
			return
		}
	}
}

// Items method returns Hosts data
func (m *VModel) Items() interface{} {
	return m.items
}

// RowCount func for print out new stuff
func (m *VModel) RowCount() int {
	return len(m.items)
}

// Checked func used for select row in tableview
func (m *VModel) Checked(row int) bool {
	return m.items[row].checked
}

// Value func used for table indexing
func (m *VModel) Value(row, col int) interface{} {
	item := m.items[row]
	switch col {
	case 1:
		return item.Mac
	case 0:
		return item.Cip
	case 4:
		return item.Opt
	case 3:
		return item.Ven
	case 2:
		return item.Let
	case 5:
		return item.Inf
	}
	panic("Internal error: tableView Value func (unexpected column)")
}

// Sort is used for sorting data in table
func (m *VModel) Sort(col int, order walk.SortOrder) error {
	m.sortColumn, m.sortOrder = col, order

	sort.SliceStable(m.items, func(i, j int) bool {
		a, b := m.items[i], m.items[j]

		c := func(ls bool) bool {
			if m.sortOrder == walk.SortAscending {
				return ls
			}

			return !ls
		}

		switch m.sortColumn {
		case 0:
			return c(bytes.Compare(net.ParseIP(a.Cip), net.ParseIP(b.Cip)) < 0)

		case 1:
			maca, _ := net.ParseMAC(a.Mac)
			macb, _ := net.ParseMAC(b.Mac)
			return c(bytes.Compare(maca, macb) < 0)

		case 2:
			milet, _ := time.ParseDuration(a.Let)
			mxlet, _ := time.ParseDuration(b.Let)
			return c(milet < mxlet)

		case 3:
			return c(a.Ven < b.Ven)

		case 4:
			return c(a.Opt < b.Opt)
		case 5:
			return c(a.Inf < b.Inf)
		}

		panic("Internal error: Sort func in tableview")
	})

	return m.SorterBase.Sort(col, order)
}

func createosfile(filePath string) (*os.File, error) {
	file, err := os.OpenFile(filePath, os.O_CREATE|os.O_WRONLY|os.O_EXCL, 0600)
	if err != nil {
		if os.IsExist(err) {
			if walk.DlgCmdNo == walk.MsgBox(globalmaingui.mainwindowsUI, "Writing file failed", fmt.Sprintf("file ‘%s’ \nalready exists, do you want to overwrite it?", filePath), walk.MsgBoxYesNo|walk.MsgBoxDefButton2|walk.MsgBoxIconWarning) {
				return nil, nil
			}
		}
	}

	file, err = os.Create(filePath)
	if err != nil {
		return nil, fmt.Errorf("%v", err)
	}

	return file, nil
}

func saveInCSV(file *os.File, ferr error) {
	if file == nil && ferr == nil {
		return
	} else if ferr != nil {
		walk.MsgBox(globalmaingui.mainwindowsUI, "OS file error", fmt.Sprint(ferr), walk.MsgBoxIconError)
		return
	} else if file == nil {
		walk.MsgBox(globalmaingui.mainwindowsUI, "OS file error", "null file passed, can not access the file", walk.MsgBoxIconError)
		return
	}

	w := csv.NewWriter(file)
	for _, record := range exdata {
		if err := w.Write(record); err != nil {
			walk.MsgBox(globalmaingui.mainwindowsUI, "OS file error", fmt.Sprint(err), walk.MsgBoxIconError)
			return
		}
	}
	w.Flush()
	if err := w.Error(); err != nil {
		walk.MsgBox(globalmaingui.mainwindowsUI, "OS file error", fmt.Sprint(err), walk.MsgBoxIconError)
		return
	}
}

func saveInTXT(file *os.File, ferr error) {
	if file == nil && ferr == nil {
		return
	} else if ferr != nil {
		walk.MsgBox(globalmaingui.mainwindowsUI, "OS file error", fmt.Sprint(ferr), walk.MsgBoxIconError)
		return
	} else if file == nil {
		walk.MsgBox(globalmaingui.mainwindowsUI, "OS file error", "null file passed, can not access the file", walk.MsgBoxIconError)
		return
	}

	for _, record := range exdata {
		for _, clumn := range record {
			if _, err := fmt.Fprintf(file, "%v\t", clumn); err != nil {
				walk.MsgBox(globalmaingui.mainwindowsUI, "OS file error", fmt.Sprint(err), walk.MsgBoxIconError)
				return
			}
		}
		if _, err := fmt.Fprint(file, "\n"); err != nil {
			walk.MsgBox(globalmaingui.mainwindowsUI, "OS file error", fmt.Sprint(err), walk.MsgBoxIconError)
			return
		}
	}

}

func runAboutDialog(form walk.Form) {
	lgg := walk.NewVBoxLayout()
	lgg.SetMargins(walk.Margins{HNear: 80, VNear: 20, HFar: 80, VFar: 20})
	lgg.SetSpacing(10)
	showingAboutDialog, err := walk.NewDialogWithFixedSize(form)
	if err != nil {
		return
	}
	defer func() {
		showingAboutDialog = nil
	}()
	showingAboutDialog.SetTitle("About GIPS")
	showingAboutDialog.SetLayout(lgg)
	gipsLbl, err := walk.NewTextLabel(showingAboutDialog)
	if err != nil {
		return
	}
	blFont, _ := walk.NewFont("Segoe UI", 16, walk.FontBold)
	gipsLbl.SetFont(blFont)
	gipsLbl.SetTextAlignment(walk.AlignHCenterVNear)
	gipsLbl.SetText("Gopher IP Scan")
	addinfo, err := walk.NewTextLabel(showingAboutDialog)
	if err != nil {
		return
	}
	addinfo.SetTextAlignment(walk.AlignHCenterVNear)
	addinfo.SetText(fmt.Sprintf("Gopher Version: 0.0.2-alpha\nGolang Version: %s\nOperating system: %s\nArchitecture: %s", strings.TrimPrefix(runtime.Version(), "go"), opRuningInfo(), runtime.GOARCH))
	copyrightLbl, err := walk.NewTextLabel(showingAboutDialog)
	if err != nil {
		return
	}
	copyrightFont, _ := walk.NewFont("Segoe UI", 8, 0)
	copyrightLbl.SetFont(copyrightFont)
	copyrightLbl.SetTextAlignment(walk.AlignHCenterVNear)
	copyrightLbl.SetText(fmt.Sprint("Copyright (c) 2020 slc.snix.ir, All rights reserved. \nDeveloped BY khokooli@gmail.com (github.com/sina-ghaderi)\nThis work is licensed under the terms of the MIT license."))
	showingAboutDialog.Run()
}

func opRuningInfo() string {
	win32sysInfo := windows.RtlGetVersion()
	var winSysType string
	switch win32sysInfo.ProductType {
	case 3:
		winSysType = " Server"
	case 2:
		winSysType = " Controller"
	}
	return fmt.Sprintf("Windows%s %d.%d.%d", winSysType, win32sysInfo.MajorVersion, win32sysInfo.MinorVersion, win32sysInfo.BuildNumber)
}

func loadSystemIcon(dll string, index int32, size int) (icon *walk.Icon) {
	icon = cachedSystemIconsForWidthAndDllIdx[widthAndDllIdx{size, index, dll}]
	if icon != nil {
		return
	}
	icon, err := walk.NewIconFromSysDLLWithSize(dll, int(index), size)
	if err == nil {
		cachedSystemIconsForWidthAndDllIdx[widthAndDllIdx{size, index, dll}] = icon
	} else {
		// if icon can not be loaded
		imgByte, _ := base64.StdEncoding.DecodeString("iVBORw0KGgoAAAANSUhEUgAAABAAAAAQCAYAAAAf8/9hAAAAvklEQVQ4T62TjQrCMAyEnf+i7/+ksg1lar6Qk1g2tsoKoaXNXe7atNmMj61tE00cv20eLJh/hhK0CehosQ9wJngFycNm1j4yAeBLUbksiALArdSIAPBtws7YNnY6yERwDulLOVDytOghkPTdUnTkoaKF4BTVywud40NFB4iLO8xlT5y7hVr/mcsVQICCfyy4Ai5P71/jxPthlWekKiquFeWpTiMN2XcNyZ0upOCqnyk7QA0/ki6lYdS631+o5A/m1C0o1nAPtQAAAABJRU5ErkJggg==")
		imgEmrg, _ := png.Decode(bytes.NewReader(imgByte))
		icon, _ := walk.NewIconFromImage(imgEmrg)
		return icon
	}
	return
}

func searchGrep(pattern string) []int {
	if pattern == serachIndexCache.search {
		return serachIndexCache.indexs
	}
	serachIndexCache = serachIndexCacheType{}
	serachIndexCache.search = pattern
	for row := 0; row < globalmaingui.ipTB.TableModel().RowCount(); row++ {
	found:
		for clm := 0; clm <= 5; clm++ {
			line := fmt.Sprint(globalmaingui.ipTB.TableModel().Value(row, clm))
			if bytes.Contains([]byte(line), []byte(pattern)) {
				serachIndexCache.indexs = append(serachIndexCache.indexs, row)
				continue found
			}
		}
	}
	return serachIndexCache.indexs
}
