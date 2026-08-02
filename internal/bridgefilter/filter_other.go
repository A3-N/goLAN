//go:build !darwin

package bridgefilter

import "fmt"

type unsupportedController struct{}

func newController() Controller {
	return unsupportedController{}
}

func (unsupportedController) Enable(string) error {
	return fmt.Errorf("fast bridge PF member filtering is supported only on macOS")
}
