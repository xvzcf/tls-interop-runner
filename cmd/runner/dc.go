// SPDX-FileCopyrightText: 2020 The tls-interop-runner Authors
// SPDX-License-Identifier: MIT

package main

import (
	"bytes"
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

type testcaseDC struct {
	name      string
	timeout   time.Duration
	outputDir string
	logger    *log.Logger
	logFile   *os.File
}

func (t *testcaseDC) getMetadata() testMetadata {
	return testMetadata{
		name:   t.name,
		abbrev: "DC",
		desc:   "Server signs handshake using delegated credentials.",
	}
}

func (t *testcaseDC) setup(verbose bool) error {
	err := os.RemoveAll(testInputsDir)
	if err != nil {
		return err
	}
	err = os.MkdirAll(testInputsDir, os.ModePerm)
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
	runLog, err := os.Create(filepath.Join(testOutputsDir, "run-log.txt"))
	if err != nil {
		runLog.Close()
		return err
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
		runLog.Close()
		return err
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
		runLog.Close()
		return err
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
		runLog.Close()
		return err
	}
	t.logger.Printf("Delegated credential algorithm: 0x%X\n", dcAlgorithm)
	t.logger.Printf("DC valid for: %v\n", dcValidFor)

	t.logFile = runLog
	return nil
}

func (t *testcaseDC) run(client endpoint, server endpoint) (result resultType, err error) {
	pc, _, _, _ := runtime.Caller(0)
	fn := runtime.FuncForPC(pc)

	cmd := exec.Command("docker", "compose", "up",
		"--renew-anon-volumes",
		"--no-build",
		"--abort-on-container-exit")

	env := os.Environ()
	env = append(env, fmt.Sprintf("SERVER=%s", server.name))
	env = append(env, fmt.Sprintf("CLIENT=%s", client.name))
	env = append(env, fmt.Sprintf("TESTCASE=%s", t.name))
	cmd.Env = env

	var cmdOut bytes.Buffer
	var stderr bytes.Buffer
	cmd.Stdout = &cmdOut
	cmd.Stderr = &stderr

	err = cmd.Start()
	if err != nil {
		err = &errorWithFnName{err: err.Error(), fnName: fn.Name()}
		result = resultError
		goto runUnsuccessful
	}

	err = waitWithTimeout(cmd, t.timeout)
	if err != nil {
		if strings.Contains(err.Error(), "exit status 64") {
			err = &errorWithFnName{err: err.Error(), fnName: fn.Name()}
			result = resultUnsupported
			goto runUnsuccessful
		}
		err = &errorWithFnName{err: err.Error(), fnName: fn.Name()}
		result = resultFailure
		goto runUnsuccessful
	}

	t.logger.Println("OUT: " + cmdOut.String())
	t.logger.Printf("%s completed without error.\n", fn.Name())
	return resultSuccess, nil

runUnsuccessful:
	t.logger.Println("OUT: " + cmdOut.String())
	t.logger.Println("ERROR: " + fmt.Sprint(err))
	t.logger.Println("STDERR: " + stderr.String())
	return result, err
}

func (t *testcaseDC) verify() (resultType, error) {
	pc, _, _, _ := runtime.Caller(0)
	fn := runtime.FuncForPC(pc)

	err := pcap.FindTshark()
	if err != nil {
		err = &errorWithFnName{err: err.Error(), fnName: fn.Name()}
		t.logger.Println(err)
		return resultError, err
	}

	pcapPath := filepath.Join(testOutputsDir, "client_node_trace.pcap")
	keylogPath := filepath.Join(testOutputsDir, "client_keylog")
	transcript, err := pcap.Parse(pcapPath, keylogPath)
	if err != nil {
		err = &errorWithFnName{err: err.Error(), fnName: fn.Name()}
		t.logger.Println(err)
		return resultError, err
	}

	err = pcap.Validate(transcript, t.name)
	if err != nil {
		err = &errorWithFnName{err: err.Error(), fnName: fn.Name()}
		t.logger.Println(err)
		return resultFailure, err
	}

	t.logger.Printf("%s completed without error.\n", fn.Name())
	return resultSuccess, nil
}

func (t *testcaseDC) teardown() error {
	t.logFile.Close()
	return nil
}
