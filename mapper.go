package main

import (
	"encoding/base64"
	"fmt"
	"gopher-scan/scream"
	"regexp"
	"time"

	"github.com/lxn/walk"
	"github.com/lxn/walk/declarative"
)

// MapperScan struct mapper setting
type MapperScan struct {
	StrPort                int
	MasgUDP                []byte
	EndPort, Gortin, TmOut int
	Connection             bool
	HostStr                string
}

func runMapperDlg(owner walk.Form, defaultip string) (int, error) {
	var guimapview struct {
		dlg                           *walk.Dialog
		startsPB, cancelPB            *walk.PushButton
		valueEdit, pEdi               *walk.NumberEdit
		dbinder                       *walk.DataBinder
		endEdit, strEdit              *walk.NumberEdit
		slv, slx                      *walk.Slider
		mesgToUDPService              *walk.Composite
		mapLineEd, mapUDPmsg, stsLine *walk.LineEdit
		rsltTextBox                   *walk.TextEdit
		progsMapperBar                *walk.ProgressBar
		resultGrpBox, optionGrpBox    *walk.GroupBox
		stopscan                      int8
	}
	const regexSingle = `^(([0-9]|[1-9][0-9]|1[0-9]{2}|2[0-4][0-9]|25[0-5])\.){3}([0-9]|[1-9][0-9]|1[0-9]{2}|2[0-4][0-9]|25[0-5])$|^(([a-zA-Z]{1})|([a-zA-Z]{1}[a-zA-Z]{1})|([a-zA-Z]{1}[0-9]{1})|([0-9]{1}[a-zA-Z]{1})|([a-zA-Z0-9][a-zA-Z0-9-_]{1,61}[a-zA-Z0-9]))\.([a-zA-Z]{2,6}|[a-zA-Z0-9-]{2,30}\.[a-zA-Z]{2,3})$`
	settmapin := &MapperScan{
		Gortin:     32,
		TmOut:      1000,
		Connection: false,
		StrPort:    20,
		EndPort:    80,
		HostStr:    defaultip,
	}

	return declarative.Dialog{
		AssignTo:      &guimapview.dlg,
		FixedSize:     true,
		Title:         "IP Scanner Port Mapper",
		DefaultButton: &guimapview.startsPB,
		CancelButton:  &guimapview.cancelPB,
		MinSize:       declarative.Size{Width: 560, Height: 350},
		Layout:        declarative.VBox{},
		OnSizeChanged: func() {

		},
		Children: []declarative.Widget{
			declarative.GroupBox{
				AssignTo: &guimapview.optionGrpBox,
				Title:    "Port Mapper Settings",
				Layout:   declarative.VBox{},
				DataBinder: declarative.DataBinder{
					AssignTo:       &guimapview.dbinder,
					Name:           "Settmapin",
					DataSource:     settmapin,
					ErrorPresenter: declarative.ToolTipErrorPresenter{},
				},
				Children: []declarative.Widget{
					declarative.Composite{
						Layout: declarative.HBox{},
						Children: []declarative.Widget{
							declarative.GroupBox{
								Title:  "Host Address To Scan",
								Layout: declarative.Grid{Columns: 1},
								Children: []declarative.Widget{
									declarative.LineEdit{
										AssignTo:    &guimapview.mapLineEd,
										ToolTipText: "format: IPv4|Domain",
										CueBanner:   "IPv4 Or Domain To Scan ...",
										Text:        settmapin.HostStr,
										OnEditingFinished: func() {
											settmapin.HostStr = guimapview.mapLineEd.Text()
										},
									},
								},
							},
							declarative.RadioButtonGroupBox{
								Title:      "Port Type To Scan",
								Layout:     declarative.HBox{},
								DataMember: "Connection",
								Buttons: []declarative.RadioButton{
									{MaxSize: declarative.Size{Width: 60}, Text: "TCP", Value: false, OnClicked: func() { guimapview.mesgToUDPService.SetVisible(false) }},
									{MaxSize: declarative.Size{Width: 60}, Text: "UDP", Value: true, OnClicked: func() { guimapview.mesgToUDPService.SetVisible(true) }},
								},
							},
							declarative.GroupBox{
								Title:  "Port Range To Scan",
								Layout: declarative.Grid{Columns: 4},
								Children: []declarative.Widget{
									declarative.NumberEdit{
										AssignTo: &guimapview.strEdit,
										MaxSize:  declarative.Size{Width: 45},
										MinSize:  declarative.Size{Width: 45},
										Value:    declarative.Bind("StrPort"),
										MinValue: 1,
										MaxValue: 65535,
										OnValueChanged: func() {
											settmapin.StrPort = int(guimapview.strEdit.Value())
											guimapview.endEdit.SetRange(guimapview.strEdit.Value(), 65535)
										},
									},
									declarative.Label{
										Text: "To:",
									},
									declarative.NumberEdit{
										AssignTo: &guimapview.endEdit,
										MaxSize:  declarative.Size{Width: 45},
										MinSize:  declarative.Size{Width: 45},
										Value:    declarative.Bind("EndPort"),
										MaxValue: 65535,
									},
								},
							},
						},
					},
					declarative.Composite{
						AssignTo: &guimapview.mesgToUDPService,
						Visible:  false,
						Layout:   declarative.HBox{},
						Children: []declarative.Widget{
							declarative.GroupBox{
								Title:  "Message To Send To UDP Services",
								Layout: declarative.Grid{Columns: 1},
								Children: []declarative.Widget{
									declarative.LineEdit{
										AssignTo:    &guimapview.mapUDPmsg,
										ToolTipText: "because UDP protocol is connection-less, mapper can't actually determine if port is open or not\nso we have to send something to UDP ports and wait for response, if nothing came back, either port is close or UDP service is not interested in our message.",
										CueBanner:   "Base64 txt message ...",
										Text:        settmapin.MasgUDP,
										OnEditingFinished: func() {
											settmapin.MasgUDP = []byte(guimapview.mapUDPmsg.Text())
										},
									},
								},
							},
						},
					},
					declarative.Composite{
						Layout: declarative.HBox{},
						Children: []declarative.Widget{
							declarative.GroupBox{
								Title:  "Scan Timeout",
								Layout: declarative.Grid{Columns: 3},
								Children: []declarative.Widget{
									declarative.Label{
										Text: "Timeoute:",
									},
									declarative.Slider{
										AssignTo: &guimapview.slx,
										Value:    declarative.Bind("TmOut"),
										MaxValue: 8192,
										MinValue: 10,
										RowSpan:  2,
										MinSize:  declarative.Size{Width: 130},

										ToolTipText: "Timeout in milliseconds",

										OnValueChanged: func() {
											settmapin.TmOut = guimapview.slx.Value()
											guimapview.pEdi.SetValue(float64(settmapin.TmOut))

										},
									},
									declarative.NumberEdit{
										AssignTo: &guimapview.pEdi,
										Value:    declarative.Bind("TmOut", declarative.Range{Min: 10, Max: 8192}),
										MaxSize:  declarative.Size{Width: 45},
										MinSize:  declarative.Size{Width: 35},
										OnValueChanged: func() {
											settmapin.TmOut = int(guimapview.pEdi.Value())
											guimapview.slx.SetValue(int(settmapin.TmOut))
										},
									},
								},
							},
							declarative.GroupBox{
								Title:  "Performace Setting",
								Layout: declarative.Grid{Columns: 3},
								Children: []declarative.Widget{
									declarative.Label{
										Text:    "Threads:",
										MinSize: declarative.Size{Width: 48},
									},
									declarative.Slider{
										AssignTo: &guimapview.slv,
										Value:    declarative.Bind("Gortin"),
										MaxValue: 256,
										MinValue: 8,
										RowSpan:  2,
										MinSize:  declarative.Size{Width: 130},

										ToolTipText: "Number of threads (GreenThreads)",

										OnValueChanged: func() {
											settmapin.Gortin = guimapview.slv.Value()
											guimapview.valueEdit.SetValue(float64(settmapin.Gortin))

										},
									},
									declarative.NumberEdit{
										AssignTo: &guimapview.valueEdit,
										MaxSize:  declarative.Size{Width: 45},
										MinSize:  declarative.Size{Width: 35},
										Value:    declarative.Bind("Gortin", declarative.Range{Min: 8, Max: 256}),
										OnValueChanged: func() {
											settmapin.Gortin = int(guimapview.valueEdit.Value())
											guimapview.slv.SetValue(settmapin.Gortin)
										},
									},
								},
							},
						},
					},
				},
			},
			declarative.GroupBox{
				AssignTo: &guimapview.resultGrpBox,
				Visible:  false,
				Title:    "Port Scan Results",
				Layout:   declarative.Grid{Columns: 1},
				Children: []declarative.Widget{
					declarative.TextEdit{
						AssignTo:   &guimapview.rsltTextBox,
						VScroll:    true,
						ReadOnly:   true,
						Background: declarative.SolidColorBrush{Color: 1513239},
						TextColor:  31248,
					},
					declarative.ProgressBar{
						AssignTo:    &guimapview.progsMapperBar,
						MinValue:    0,
						MaxValue:    100,
						ToolTipText: "Progress Bar",
						MaxSize:     declarative.Size{Height: 19},
						Visible:     false,
					},
					declarative.LineEdit{
						AssignTo: &guimapview.stsLine,
						Visible:  false,
						ReadOnly: true,
					},
				},
			},
			declarative.Composite{
				Layout: declarative.HBox{},
				Children: []declarative.Widget{
					declarative.HSpacer{},
					declarative.PushButton{
						AssignTo: &guimapview.startsPB,
						Text:     "Start Scan",
						OnClicked: func() {
							if guimapview.stopscan == 0 {
								if err := guimapview.dbinder.Submit(); err != nil {
									return
								}
								if settmapin.HostStr == "" {
									guimapview.mapLineEd.SetFocus()
									return
								}
								if match, _ := regexp.MatchString(regexSingle, settmapin.HostStr); !match {
									walk.MsgBox(guimapview.dlg, "Host syntax error", "Invalid IPv4 or Domain address, format: IPv4|Domain\nExample: slc.snix.ir", walk.MsgBoxIconError)
									return
								}
								guimapview.stopscan = 1
								guimapview.startsPB.SetText("Stop Scan")

								if settmapin.Connection {
									var err error
									settmapin.MasgUDP, err = base64.StdEncoding.DecodeString(string(settmapin.MasgUDP))
									if err != nil {
										walk.MsgBox(guimapview.dlg, "Base64 Error", "Error in Decoding base64 message", walk.MsgBoxIconError)
									}

								}
								var portlist []int
								var jobdn, lenopen int
								for i := settmapin.StrPort; i <= settmapin.EndPort; i++ {
									portlist = append(portlist, i)
								}
								guimapview.optionGrpBox.SetVisible(false)
								guimapview.resultGrpBox.SetVisible(true)
								guimapview.progsMapperBar.SetVisible(true)
								guimapview.stsLine.SetVisible(true)
								guimapview.rsltTextBox.SetText(fmt.Sprintf("Starting Mapper (gips.snix.ir) at %v Interesting ports on %v --- %v\r\nPORT\t\tSTATE\t\tSERVICE\r\n", time.Now(), settmapin.HostStr, oprationStat(settmapin.HostStr)))
								ch := make(chan scream.ScanResults)
								go scream.CustomPscan(settmapin.HostStr, time.Duration(settmapin.TmOut)*time.Millisecond, int64(settmapin.Gortin), portlist, settmapin.MasgUDP, settmapin.Connection, ch)
								go func() {
									for i := range ch {
										if statpx, numb := i.StatInfo(); statpx {
											lenopen++
											guimapview.rsltTextBox.SetText(guimapview.rsltTextBox.Text() + fmt.Sprintf("%v/%v\t\t%v\t\t%v\r\n", numb, i.SigPort(), "open", i.PortInfo()))
										}
										jobdn++
										prcstatus := 100 - (float64(len(portlist)-jobdn)/float64(len(portlist)))*float64(100)
										guimapview.progsMapperBar.SetValue(int(prcstatus))
										guimapview.stsLine.SetText(fmt.Sprintf("Progress: %.2f%%\t\tTotal: %v\t\tChecked: %v\t\tOpen: %v", prcstatus, len(portlist), jobdn, lenopen))
									}
									guimapview.stopscan = 2
									guimapview.startsPB.SetText("Back To Scan")
									guimapview.startsPB.SetEnabled(true)
									guimapview.progsMapperBar.SetVisible(false)
									guimapview.stsLine.SetVisible(false)
									guimapview.progsMapperBar.SetValue(0)
									guimapview.stsLine.SetText("Progress: 0\t\tTotal: 0\t\tChecked: 0\t\tOpen: 0")

								}()
							} else if guimapview.stopscan == 1 {
								scream.StopChan <- struct{}{}
								guimapview.startsPB.SetEnabled(false)
							} else {
								guimapview.stopscan = 0
								guimapview.optionGrpBox.SetVisible(true)
								guimapview.resultGrpBox.SetVisible(false)
								guimapview.startsPB.SetText("Start Scan")

							}
						},
					},
					declarative.PushButton{
						AssignTo:  &guimapview.cancelPB,
						Text:      "Close",
						OnClicked: func() { guimapview.dlg.Cancel() },
					},
				},
			},
		},
	}.Run(owner)
}

func oprationStat(addr string) string {
	ipv4add, reptime, err := scream.PingHost(addr, 1)
	if err != nil {
		return fmt.Sprintf("Host %v Latency: %v", ipv4add, err)
	}
	return fmt.Sprintf("Host %v Latency: %v", ipv4add, reptime)
}
