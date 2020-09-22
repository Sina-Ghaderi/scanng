package main

import (
	"github.com/lxn/walk"
	"github.com/lxn/walk/declarative"
)

func runSettingsDG(owner walk.Form, settings *SerIPscan) (int, error) {

	var settingsGuiHolder struct {
		dlg                *walk.Dialog
		db                 *walk.DataBinder
		acceptPB, cancelPB *walk.PushButton
		valueEdit, pEdi    *walk.NumberEdit
		slv, slx           *walk.Slider
		gbox, gpibox       *walk.GroupBox
	}
	return declarative.Dialog{
		AssignTo:      &settingsGuiHolder.dlg,
		FixedSize:     true,
		Title:         "IP Scanner Settings",
		DefaultButton: &settingsGuiHolder.acceptPB,
		CancelButton:  &settingsGuiHolder.cancelPB,
		DataBinder: declarative.DataBinder{
			AssignTo:       &settingsGuiHolder.db,
			Name:           "Setting",
			DataSource:     settings,
			ErrorPresenter: declarative.ToolTipErrorPresenter{},
		},
		MinSize: declarative.Size{Width: 300, Height: 300},
		Layout:  declarative.VBox{},
		Children: []declarative.Widget{
			declarative.GroupBox{
				Title:  "IP Scanner Settings",
				Layout: declarative.VBox{},
				Children: []declarative.Widget{
					declarative.Composite{
						Layout: declarative.Grid{Columns: 1},
						Children: []declarative.Widget{
							declarative.Composite{
								Layout: declarative.HBox{Spacing: 0},
								Children: []declarative.Widget{
									declarative.RadioButtonGroupBox{
										Title:      "Port Scan",
										Layout:     declarative.Grid{Columns: 1},
										DataMember: "PscanTOF",
										Buttons: []declarative.RadioButton{
											{MaxSize: declarative.Size{Width: 60}, Text: "True", Value: true, OnClicked: func() { settingsGuiHolder.gbox.SetEnabled(true) }},
											{MaxSize: declarative.Size{Width: 60}, Text: "False", Value: false, OnClicked: func() { settingsGuiHolder.gbox.SetEnabled(false) }},
										},
									},
									declarative.RadioButtonGroupBox{
										Title:      "Manufacture",
										Layout:     declarative.Grid{Columns: 1},
										DataMember: "NetBs",
										Buttons: []declarative.RadioButton{
											{MaxSize: declarative.Size{Width: 60}, Text: "True", Value: true},
											{MaxSize: declarative.Size{Width: 60}, Text: "False", Value: false},
										},
									},
									declarative.RadioButtonGroupBox{
										Title:      "Ping Hosts",
										Layout:     declarative.Grid{Columns: 1},
										DataMember: "Pong",
										Buttons: []declarative.RadioButton{
											{Text: "True", Value: true, MaxSize: declarative.Size{Width: 60}, OnClicked: func() { settingsGuiHolder.gpibox.SetEnabled(true) }},
											{Text: "False", Value: false, MaxSize: declarative.Size{Width: 60}, OnClicked: func() { settingsGuiHolder.gpibox.SetEnabled(false) }},
										},
									},
								},
							},
							declarative.GroupBox{
								AssignTo: &settingsGuiHolder.gbox,
								Title:    "Port Number To Scan",
								Layout:   declarative.Grid{Columns: 4},
								Children: []declarative.Widget{
									declarative.Label{
										Text: "Port Number:",
									},
									declarative.NumberEdit{
										MaxSize: declarative.Size{Width: 45},
										Value:   declarative.Bind("Pscan1.Nm", declarative.Range{Min: 1, Max: 65535}),
									},
									declarative.RadioButtonGroup{
										DataMember: "Pscan1.Tp",
										Buttons: []declarative.RadioButton{
											{Text: "TCP", Value: "TCP", MaxSize: declarative.Size{Width: 55}},
											{Text: "UDP", Value: "UDP", MaxSize: declarative.Size{Width: 55}},
										},
									},
									declarative.Label{
										Text: "Port Number:",
									},
									declarative.NumberEdit{
										MaxSize: declarative.Size{Width: 45},
										Value:   declarative.Bind("Pscan2.Nm", declarative.Range{Min: 1, Max: 65535}),
									},
									declarative.RadioButtonGroup{
										DataMember: "Pscan2.Tp",
										Buttons: []declarative.RadioButton{
											{Text: "TCP", Value: "TCP", MaxSize: declarative.Size{Width: 55}},
											{Text: "UDP", Value: "UDP", MaxSize: declarative.Size{Width: 55}},
										},
									},
									declarative.Label{
										Text: "Port Number:",
									},
									declarative.NumberEdit{
										MaxSize: declarative.Size{Width: 45},
										Value:   declarative.Bind("Pscan3.Nm", declarative.Range{Min: 1, Max: 65535}),
									},
									declarative.RadioButtonGroup{
										DataMember: "Pscan3.Tp",
										Buttons: []declarative.RadioButton{
											{Text: "TCP", Value: "TCP", MaxSize: declarative.Size{Width: 55}},
											{Text: "UDP", Value: "UDP", MaxSize: declarative.Size{Width: 55}},
										},
									},
									declarative.Label{
										Text: "Port Number:",
									},
									declarative.NumberEdit{
										MaxSize: declarative.Size{Width: 45},
										Value:   declarative.Bind("Pscan4.Nm", declarative.Range{Min: 1, Max: 65535}),
									},
									declarative.RadioButtonGroup{
										DataMember: "Pscan4.Tp",
										Buttons: []declarative.RadioButton{
											{Text: "TCP", Value: "TCP", MaxSize: declarative.Size{Width: 55}},
											{Text: "UDP", Value: "UDP", MaxSize: declarative.Size{Width: 55}},
										},
									},
									declarative.Label{
										Text: "Port Number:",
									},
									declarative.NumberEdit{
										MaxSize: declarative.Size{Width: 45},
										Value:   declarative.Bind("Pscan5.Nm", declarative.Range{Min: 1, Max: 65535}),
									},
									declarative.RadioButtonGroup{
										DataMember: "Pscan5.Tp",
										Buttons: []declarative.RadioButton{
											{Text: "TCP", Value: "TCP", MaxSize: declarative.Size{Width: 55}},
											{Text: "UDP", Value: "UDP", MaxSize: declarative.Size{Width: 55}},
										},
									},
								},
							},
							declarative.GroupBox{
								AssignTo: &settingsGuiHolder.gpibox,
								Title:    "Ping Timeout",
								Layout:   declarative.Grid{Columns: 3},
								Children: []declarative.Widget{
									declarative.Label{
										Text: "Timeoute:",
									},
									declarative.Slider{
										AssignTo: &settingsGuiHolder.slx,
										Value:    declarative.Bind("Ptime"),
										MaxValue: 8,
										MinValue: 1,
										RowSpan:  2,
										MinSize:  declarative.Size{Width: 130},

										ToolTipText: "Timeout in second",

										OnValueChanged: func() {
											settings.Ptime = settingsGuiHolder.slx.Value()
											settingsGuiHolder.pEdi.SetValue(float64(settings.Ptime))

										},
									},
									declarative.NumberEdit{
										AssignTo: &settingsGuiHolder.pEdi,
										Value:    declarative.Bind("Ptime", declarative.Range{Min: 1, Max: 8}),
										MaxSize:  declarative.Size{Width: 45},
										OnValueChanged: func() {
											settings.Ptime = int(settingsGuiHolder.pEdi.Value())
											settingsGuiHolder.slx.SetValue(int(settings.Ptime))
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
										AssignTo: &settingsGuiHolder.slv,
										Value:    declarative.Bind("GreenThreads"),
										MaxValue: 256,
										MinValue: 8,
										RowSpan:  2,
										MinSize:  declarative.Size{Width: 130},

										ToolTipText: "Number of threads (GreenThreads)",

										OnValueChanged: func() {
											settings.GreenThreads = settingsGuiHolder.slv.Value()
											settingsGuiHolder.valueEdit.SetValue(float64(settings.GreenThreads))

										},
									},
									declarative.NumberEdit{
										AssignTo: &settingsGuiHolder.valueEdit,
										MaxSize:  declarative.Size{Width: 45},
										Value:    declarative.Bind("GreenThreads", declarative.Range{Min: 8, Max: 256}),
										OnValueChanged: func() {
											settings.GreenThreads = int(settingsGuiHolder.valueEdit.Value())
											settingsGuiHolder.slv.SetValue(settings.GreenThreads)
										},
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
						AssignTo: &settingsGuiHolder.acceptPB,
						Text:     "OK",
						OnClicked: func() {
							if err := settingsGuiHolder.db.Submit(); err != nil {
								return
							}

							settingsGuiHolder.dlg.Accept()
						},
					},
					declarative.PushButton{
						AssignTo:  &settingsGuiHolder.cancelPB,
						Text:      "Cancel",
						OnClicked: func() { settingsGuiHolder.dlg.Cancel() },
					},
				},
			},
		},
	}.Run(owner)
}
