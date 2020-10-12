package api

import (
	"log"
	"os/exec"
)

func ExecScript(scriptName string, wgInterface string) error {
	path := "../scripts/" + scriptName

	start := exec.Command("sh", path, wgInterface)
	out, err := start.CombinedOutput()
	if err != nil {
		log.Printf("Error executing %s: %s", scriptName, out)
		return err
	}
	return nil
}
