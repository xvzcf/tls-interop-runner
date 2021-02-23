// SPDX-FileCopyrightText: 2020 The tls-interop-runner Authors
// SPDX-License-Identifier: MIT

package pcap

import (
	"errors"
	"os/exec"
	"strconv"
	"strings"
)

var tsharkPath string

// FindTshark looks for a sufficiently recent version of Tshark in the PATH,
// and if it finds it, sets tsharkPath for use by Parse().
func FindTshark() (err error) {
	tsharkPath, err = exec.LookPath("tshark")
	if err != nil {
		return err
	}

	tsharkConfiguration, err := exec.Command(tsharkPath, "--version").Output()
	if err != nil {
		return err
	}

	tsharkVersionLine := strings.Split(string(tsharkConfiguration), "\n")[0]
	tsharkVersionFields := strings.Split(strings.Fields(tsharkVersionLine)[2], ".")
	tsharkMajorVersion, err := strconv.Atoi(tsharkVersionFields[0])
	if err != nil {
		return err
	}

	tsharkMinorVersion, err := strconv.Atoi(tsharkVersionFields[1])
	if err != nil {
		return err
	}

	if tsharkMajorVersion < 3 || tsharkMinorVersion < 2 {
		return errors.New("requires tshark with version >= 3.2.0")
	}

	return nil
}
