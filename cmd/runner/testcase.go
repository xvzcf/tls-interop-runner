// SPDX-FileCopyrightText: 2020 The tls-interop-runner Authors
// SPDX-License-Identifier: MIT

package main

import (
	"bytes"
	"errors"
	"fmt"
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
	setup() error
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
}

func (t *testCaseDC) setup() error {
	err := os.MkdirAll(testInputsDir, os.ModePerm)
	if err != nil {
		return err
	}
	err = os.RemoveAll(testOutputsDir)
	if err != nil {
		return err
	}
	err = os.MkdirAll(testOutputsDir, os.ModePerm)
	if err != nil {
		return err
	}

	var inputParams strings.Builder

	rootSignatureAlgorithm := utils.SignatureECDSAWithP521AndSHA512
	err = utils.MakeRootCertificate(
		&utils.Config{
			Hostnames:          []string{"root.com"},
			ValidFrom:          time.Now(),
			ValidFor:           365 * 25 * time.Hour,
			SignatureAlgorithm: rootSignatureAlgorithm,
		},
		filepath.Join(testInputsDir, "root.crt"),
		filepath.Join(testInputsDir, "root.key"),
	)
	if err != nil {
		return err
	}
	inputParams.WriteString(fmt.Sprintf("Root certificate algorithm: 0x%X\n", rootSignatureAlgorithm))

	intermediateSignatureAlgorithm := utils.SignatureECDSAWithP256AndSHA256
	err = utils.MakeIntermediateCertificate(
		&utils.Config{
			Hostnames:          []string{"example.com"},
			ValidFrom:          time.Now(),
			ValidFor:           365 * 25 * time.Hour,
			SignatureAlgorithm: intermediateSignatureAlgorithm,
			ForDC:              true,
		},
		filepath.Join(testInputsDir, "root.crt"),
		filepath.Join(testInputsDir, "root.key"),
		filepath.Join(testInputsDir, "example.crt"),
		filepath.Join(testInputsDir, "example.key"),
	)
	if err != nil {
		return err
	}
	inputParams.WriteString(fmt.Sprintf("Intermediate certificate algorithm: 0x%X\n", intermediateSignatureAlgorithm))

	dcAlgorithm := utils.SignatureECDSAWithP256AndSHA256
	dcValidFor := 24 * time.Hour
	err = utils.MakeDelegatedCredential(
		&utils.Config{
			ValidFor:           dcValidFor,
			SignatureAlgorithm: dcAlgorithm,
		},
		&utils.Config{},
		filepath.Join(testInputsDir, "example.crt"),
		filepath.Join(testInputsDir, "example.key"),
		filepath.Join(testInputsDir, "dc.txt"),
	)
	if err != nil {
		return err
	}
	inputParams.WriteString(fmt.Sprintf("Delegated credential algorithm: 0x%X\n", intermediateSignatureAlgorithm))
	inputParams.WriteString(fmt.Sprintf("DC valid for: %v\n", dcValidFor))

	inputParamsLog, err := os.Create(filepath.Join(testOutputsDir, "input-params.txt"))
	if err != nil {
		return err
	}
	defer inputParamsLog.Close()

	_, err = inputParamsLog.WriteString(inputParams.String())
	if err != nil {
		return err
	}

	return nil
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
	// should be built and tagged by this point. They're just set to avoid
	// unset variable warnings by docker-compose.
	env = append(env, "SERVER_SRC=\"\"")
	env = append(env, "CLIENT_SRC=\"\"")

	cmd.Env = env

	var cmdOut bytes.Buffer
	cmd.Stdout = &cmdOut
	cmd.Stderr = &cmdOut

	testLog, err := os.Create(filepath.Join(testOutputsDir, "test.txt"))
	if err != nil {
		return &testError{err: fmt.Sprintf("os.Create failed: %s", err), funcName: fn.Name()}
	}

	err = cmd.Start()
	if err != nil {
		_, _ = testLog.WriteString(fmt.Sprintf("%s,%s,%s,%s", client.name, server.name, t.name, "error"))
		return &testError{err: fmt.Sprintf("docker-compose up start(): %s", err), funcName: fn.Name()}
	}

	err = waitWithTimeout(cmd, t.timeout)
	if err != nil {
		if strings.Contains(err.Error(), "exit status 64") {
			_, _ = testLog.WriteString(fmt.Sprintf("%s,%s,%s,%s", client.name, server.name, t.name, "skipped"))
			return &testError{err: fmt.Sprintf("docker-compose up: %s", err), funcName: fn.Name(), unsupported: true}
		}
		_, _ = testLog.WriteString(fmt.Sprintf("%s,%s,%s,%s", client.name, server.name, t.name, "failed"))
		return &testError{err: fmt.Sprintf("docker-compose up: %s", err), funcName: fn.Name()}
	}
	if *verboseMode {
		log.Println(cmdOut.String())
	}

	_, _ = testLog.WriteString(fmt.Sprintf("%s,%s,%s,%s", client.name, server.name, t.name, "success"))
	runLog, err := os.Create(filepath.Join(testOutputsDir, "run.txt"))
	if err != nil {
		return &testError{err: fmt.Sprintf("os.Create failed: %s", err), funcName: fn.Name()}
	}
	_, err = runLog.WriteString(cmdOut.String())
	if err != nil {
		return &testError{err: fmt.Sprintf("WriteString failed: %s", err), funcName: fn.Name()}
	}

	return nil
}

func (t *testCaseDC) verify() error {
	pc, _, _, _ := runtime.Caller(0)
	fn := runtime.FuncForPC(pc)

	err := pcap.FindTshark()
	if err != nil {
		return &testError{err: fmt.Sprintf("tshark not found: %s", err), funcName: fn.Name()}
	}

	pcapPath := filepath.Join(testOutputsDir, "client_node_trace.pcap")
	keylogPath := filepath.Join(testOutputsDir, "client_keylog")
	transcript, err := pcap.Parse(pcapPath, keylogPath)
	if err != nil {
		return &testError{err: fmt.Sprintf("could not parse pcap: %s", err), funcName: fn.Name()}
	}

	err = pcap.Validate(transcript, t.name)
	if err != nil {
		return &testError{err: fmt.Sprintf("could not validate pcap: %s", err), funcName: fn.Name()}
	}
	return nil
}

var testCases = map[string]testCase{
	"dc": &testCaseDC{
		name:    "dc",
		timeout: 100 * time.Second},
}
