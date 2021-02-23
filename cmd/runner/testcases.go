package main

import (
	"fmt"
	"os"
	"os/exec"
	"path"
	"time"

	"github.com/xvzcf/tls-interop-runner/internal/utils"
)

type testcase interface {
	generateInputs() error
	run(client endpoint, server endpoint) error
	verify() error
}

type testcaseDC struct {
	timeout int
}

func (t testcaseDC) generateInputs() error {
	os.MkdirAll(testInputsDir, os.ModePerm)

	err := utils.MakeRootCertificate(
		&utils.Config{
			Hostnames:          []string{"root.com"},
			ValidFrom:          time.Now(),
			ValidFor:           365 * 25 * time.Hour,
			SignatureAlgorithm: utils.SignatureECDSAWithP521AndSHA512,
		},
		path.Join(testInputsDir, "root.crt"),
		path.Join(testInputsDir, "root.key"),
	)
	if err != nil {
		return err
	}
	err = utils.MakeIntermediateCertificate(
		&utils.Config{
			Hostnames:          []string{"example.com"},
			ValidFrom:          time.Now(),
			ValidFor:           365 * 25 * time.Hour,
			SignatureAlgorithm: utils.SignatureECDSAWithP256AndSHA256,
			ForDC:              true,
		},
		path.Join(testInputsDir, "root.crt"),
		path.Join(testInputsDir, "root.key"),
		path.Join(testInputsDir, "example.crt"),
		path.Join(testInputsDir, "example.key"),
	)
	if err != nil {
		return err
	}
	err = utils.MakeDelegatedCredential(
		&utils.Config{
			ValidFor:           24 * time.Hour,
			SignatureAlgorithm: uint16(0x0807),
		},
		&utils.Config{},
		path.Join(testInputsDir, "example.crt"),
		path.Join(testInputsDir, "example.key"),
		path.Join(testInputsDir, "dc.txt"),
	)
	if err != nil {
		return err
	}
	return nil
}

func (t testcaseDC) run(client endpoint, server endpoint) error {
	cmd := exec.Command("docker-compose", "up",
		"--build",
		"-V",
		"--abort-on-container-exit")

	cmd.Env = os.Environ()
	if server.regression {
		cmd.Env = append(cmd.Env, "SERVER_SRC=./regression-endpoints")
	} else {
		cmd.Env = append(cmd.Env, "SERVER_SRC=./impl-endpoints")
	}
	cmd.Env = append(cmd.Env, fmt.Sprintf("SERVER=%s", server.name))
	if client.regression {
		cmd.Env = append(cmd.Env, "CLIENT_SRC=./regression-endpoints")
	} else {
		cmd.Env = append(cmd.Env, "CLIENT_SRC=./impl-endpoints")
	}
	cmd.Env = append(cmd.Env, fmt.Sprintf("CLIENT=%s", client.name))
	cmd.Env = append(cmd.Env, "TESTCASE=dc")

	outputFile, err := os.Create(path.Join(testOutputsDir, "output.txt"))
	if err != nil {
		return fmt.Errorf("output file creation failed: %s", err)
	}
	defer outputFile.Close()
	cmd.Stdout = outputFile

	err = cmd.Start()
	if err != nil {
		return fmt.Errorf("docker-compose up failed: %s", err)
	}
	err = cmd.Wait()
	if err != nil {
		return fmt.Errorf("docker-compose up failed: %s", err)
	}
	return nil
}

func (t testcaseDC) verify() error {
	return nil
}

var testcases = map[string]testcase{
	"dc": testcaseDC{},
}
