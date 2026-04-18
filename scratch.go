package main

import (
	"fmt"
	"github.com/charmbracelet/lipgloss"
)

func main() {
	cardA := lipgloss.NewStyle().Border(lipgloss.RoundedBorder()).BorderForeground(lipgloss.Color("202")).Padding(1, 2).Width(30).Render("● en12\nDevice Port\nMAC: 00:e0:4c:68:01:24\nMTU: 1500")
	cardB := lipgloss.NewStyle().Border(lipgloss.RoundedBorder()).BorderForeground(lipgloss.Color("201")).Padding(1, 2).Width(30).Render("● en11\nSwitch Port\nMAC: 6c:1f:f7:58:b5:fa\nMTU: 1500")
	middleManBox := lipgloss.NewStyle().Border(lipgloss.RoundedBorder()).BorderForeground(lipgloss.Color("46")).Foreground(lipgloss.Color("46")).Bold(true).Padding(1, 2).Render("Middle Man")
	wire := lipgloss.NewStyle().Foreground(lipgloss.Color("46")).Bold(true).Render(" ══════ ")

	res := "  " + lipgloss.JoinHorizontal(lipgloss.Center, cardA, wire, middleManBox, wire, cardB)
	fmt.Println(res)
}
