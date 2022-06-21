// SPDX-FileCopyrightText: 2020 The tls-interop-runner Authors
// SPDX-License-Identifier: MIT

package main

import (
	"errors"
	"fmt"
	"os/exec"
	"time"
)

type errorWithFnName struct {
	err    string
	fnName string
}

func (e *errorWithFnName) Error() string {
	return fmt.Sprintf("%s(): %s", e.fnName, e.err)
}

func waitWithTimeout(cmd *exec.Cmd, timeout time.Duration) error {
	done := make(chan error)
	go func() {
		done <- cmd.Wait()
	}()
	select {
	case <-time.After(timeout):
		if err := cmd.Process.Kill(); err != nil {
			return fmt.Errorf("failed to kill process:%s", err)
		}
		return errors.New("process timed out")
	case err := <-done:
		if err != nil {
			close(done)
			return err
		}
		return nil
	}
}

type resultType uint

const (
	resultError       resultType = iota
	resultFailure     resultType = iota
	resultSuccess     resultType = iota
	resultUnsupported resultType = iota
)

func (rt resultType) String() string {
	switch rt {
	case resultError:
		return "Error"
	case resultFailure:
		return "Failure"
	case resultSuccess:
		return "Success"
	case resultUnsupported:
		return "Skipped"
	default:
		return ""
	}
}

type testcase interface {
	setup(verbose bool) error
	run(client endpoint, server endpoint) (resultType, error)
	verify() (resultType, error)
	teardown(moveOutputs bool) error
}

var testcases = map[string]testcase{
	"dc": &testcaseDC{
		name:    "dc",
		timeout: 100 * time.Second},
	"ech-accept": &testcaseECHAccept{
		name:    "ech-accept",
		timeout: 100 * time.Second},
}
