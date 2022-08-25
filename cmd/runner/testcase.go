// SPDX-FileCopyrightText: 2020 The tls-interop-runner Authors
// SPDX-License-Identifier: MIT

package main

import (
	"errors"
	"fmt"
	"io"
	"log"
	"os"
	"os/exec"
	"path/filepath"
	"sort"
	"time"
)

type testMetadata struct {
	name   string
	abbrev string
	desc   string
}

type testcase interface {
	getMetadata() testMetadata
	setup(verbose bool) error
	run(client endpoint, server endpoint) (resultType, error)
	verify() (resultType, error)
	teardown() error
}

var testcases = map[string]testcase{
	"dc": &testcaseDC{
		name:    "dc",
		timeout: 100 * time.Second},
	"ech-accept": &testcaseECHAccept{
		name:    "ech-accept",
		timeout: 100 * time.Second},
}

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
	resultSkipped     resultType = iota
)

func (rt resultType) String() string {
	switch rt {
	case resultError:
		return "error"
	case resultFailure:
		return "failed"
	case resultSuccess:
		return "succeeded"
	case resultUnsupported:
		return "unsupported"
	case resultSkipped:
		return "skipped"
	default:
		return ""
	}
}

func doTestcase(t testcase, testName string, client endpoint, server endpoint, verbose bool) (resultType, error) {
	log.Println("Testing: " + testName)
	var result resultType

	err := t.setup(verbose)
	if err != nil {
		goto teardown
	}

	result, err = t.run(client, server)
	if result != resultSuccess {
		goto teardown
	}

	result, err = t.verify()

teardown:
	testcaseError := err

	testStatusFile, err := os.Create(filepath.Join(testOutputsDir, "test.txt"))
	if err != nil {
		return resultError, fmt.Errorf("error creating test status file: %s", err)
	}
	defer testStatusFile.Close()

	testStatusLogger := log.New(io.MultiWriter(os.Stdout, testStatusFile), "", 0)

	if testcaseError != nil {
		testStatusLogger.Printf("%s,%s,%s,%v,%s", client.name, server.name, testName, result, testcaseError)
	} else {
		testStatusLogger.Printf("%s,%s,%s,%v", client.name, server.name, testName, result)
	}

	err = t.teardown()
	if err != nil {
		return resultError, fmt.Errorf("Error tearing down: %s", err)
	}

	return result, testcaseError
}

func getTestcaseNamesSorted() []string {
	var testcaseNames []string
	for name := range testcases {
		testcaseNames = append(testcaseNames, name)
	}
	sort.Strings(testcaseNames)
	return testcaseNames
}
