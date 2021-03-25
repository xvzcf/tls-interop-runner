// SPDX-FileCopyrightText: 2020 The tls-interop-runner Authors
// SPDX-License-Identifier: MIT

package main

import (
	"bytes"
	"errors"
	"fmt"
	"io"
	"log"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"time"

	"github.com/xvzcf/tls-interop-runner/internal/pcap"
	"github.com/xvzcf/tls-interop-runner/internal/utils"
)

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

type testCase interface {
	setup(verbose bool) (*os.File, error)
	run(client endpoint, server endpoint) error
	verify() error
}

type testError struct {
	err         string
	funcName    string
	unsupported bool
}

func (e *testError) Error() string {
	if e.unsupported {
		return fmt.Sprintf("Unsupported,%s(): %s", e.funcName, e.err)
	}
	return fmt.Sprintf("Failure,%s(): %s", e.funcName, e.err)
}

type testCaseDC struct {
	name      string
	timeout   time.Duration
	outputDir string
	logger    *log.Logger
}

func (t *testCaseDC) setup(verbose bool) (*os.File, error) {
	err := os.MkdirAll(testInputsDir, os.ModePerm)
	if err != nil {
		return nil, err
	}
	err = os.RemoveAll(testOutputsDir)
	if err != nil {
		return nil, err
	}
	err = os.MkdirAll(testOutputsDir, os.ModePerm)
	if err != nil {
		return nil, err
	}
	runLog, err := os.Create(filepath.Join(testOutputsDir, "run-log.txt"))
	if err != nil {
		return nil, err
	}
	if verbose {
		t.logger = log.New(io.MultiWriter(os.Stdout, runLog),
			"",
			log.Ldate|log.Ltime|log.Lshortfile)
	} else {
		t.logger = log.New(io.Writer(runLog),
			"",
			log.Ldate|log.Ltime|log.Lshortfile)
	}

	rootSignatureAlgorithm, err := utils.MakeRootCertificate(
		&utils.Config{
			Hostnames: []string{"root.com"},
			ValidFrom: time.Now(),
			ValidFor:  365 * 25 * time.Hour,
		},
		filepath.Join(testInputsDir, "root.crt"),
		filepath.Join(testInputsDir, "root.key"),
	)
	if err != nil {
		return runLog, err
	}
	t.logger.Printf("Root certificate algorithm: 0x%X\n", rootSignatureAlgorithm)

	intermediateSignatureAlgorithm, err := utils.MakeIntermediateCertificate(
		&utils.Config{
			Hostnames: []string{"example.com"},
			ValidFrom: time.Now(),
			ValidFor:  365 * 25 * time.Hour,
			ForDC:     true,
		},
		filepath.Join(testInputsDir, "root.crt"),
		filepath.Join(testInputsDir, "root.key"),
		filepath.Join(testInputsDir, "example.crt"),
		filepath.Join(testInputsDir, "example.key"),
	)
	if err != nil {
		return runLog, err
	}
	t.logger.Printf("Intermediate certificate algorithm: 0x%X\n", intermediateSignatureAlgorithm)

	dcValidFor := 24 * time.Hour
	dcAlgorithm, err := utils.MakeDelegatedCredential(
		&utils.Config{
			ValidFor: dcValidFor,
		},
		filepath.Join(testInputsDir, "example.crt"),
		filepath.Join(testInputsDir, "example.key"),
		filepath.Join(testInputsDir, "dc.txt"),
	)
	if err != nil {
		return runLog, err
	}
	t.logger.Printf("Delegated credential algorithm: 0x%X\n", dcAlgorithm)
	t.logger.Printf("DC valid for: %v\n", dcValidFor)

	return runLog, nil
}

func (t *testCaseDC) run(client endpoint, server endpoint) error {
	pc, _, _, _ := runtime.Caller(0)
	fn := runtime.FuncForPC(pc)

	cmd := exec.Command("docker-compose", "up",
		"-V",
		"--no-build",
		"--abort-on-container-exit")

	env := os.Environ()
	env = append(env, fmt.Sprintf("SERVER=%s", server.name))
	env = append(env, fmt.Sprintf("CLIENT=%s", client.name))
	env = append(env, fmt.Sprintf("TESTCASE=%s", t.name))
	// SERVER_SRC and CLIENT_SRC should not be needed, since the images
	// should be built and tagged by this point. They're just set to suppress
	// unset variable warnings by docker-compose.
	env = append(env, "SERVER_SRC=\"\"")
	env = append(env, "CLIENT_SRC=\"\"")
	cmd.Env = env

	var cmdOut bytes.Buffer
	cmd.Stdout = &cmdOut
	cmd.Stderr = &cmdOut

	err := cmd.Start()
	if err != nil {
		err = &testError{err: fmt.Sprintf("docker-compose up start(): %s", err), funcName: fn.Name()}
		goto runError
	}

	err = waitWithTimeout(cmd, t.timeout)
	if err != nil {
		if strings.Contains(err.Error(), "exit status 64") {
			err = &testError{err: fmt.Sprintf("docker-compose up: %s", err), funcName: fn.Name(), unsupported: true}
		}
		err = &testError{err: fmt.Sprintf("docker-compose up: %s", err), funcName: fn.Name()}
		goto runError
	}

	t.logger.Print(cmdOut.String())
	t.logger.Printf("%s completed without error.\n", fn.Name())
	return nil

runError:
	t.logger.Println(cmdOut.String())
	t.logger.Println(err)
	return err
}

func (t *testCaseDC) verify() error {
	pc, _, _, _ := runtime.Caller(0)
	fn := runtime.FuncForPC(pc)

	err := pcap.FindTshark()
	if err != nil {
		err = &testError{err: fmt.Sprintf("tshark not found: %s", err), funcName: fn.Name()}
		t.logger.Println(err)
		return err
	}

	pcapPath := filepath.Join(testOutputsDir, "client_node_trace.pcap")
	keylogPath := filepath.Join(testOutputsDir, "client_keylog")
	transcript, err := pcap.Parse(pcapPath, keylogPath)
	if err != nil {
		err = &testError{err: fmt.Sprintf("could not parse pcap: %s", err), funcName: fn.Name()}
		t.logger.Println(err)
		return err
	}

	err = pcap.Validate(transcript, t.name)
	if err != nil {
		err = &testError{err: fmt.Sprintf("could not validate pcap: %s", err), funcName: fn.Name()}
		t.logger.Println(err)
		return err
	}

	t.logger.Printf("%s completed without error.\n", fn.Name())
	return nil
}

var testCases = map[string]testCase{
	"dc": &testCaseDC{
		name:    "dc",
		timeout: 100 * time.Second},
}
