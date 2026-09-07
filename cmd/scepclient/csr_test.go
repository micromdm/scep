package main

import (
	"crypto/rand"
	"crypto/rsa"
	"os"
	"path/filepath"
	"testing"
)

func TestResolvePaths(t *testing.T) {
	keyPath := filepath.Join("testdir", "serverA.key")

	// Test 1: Default paths when cert and csr are not specified
	certPath, csrPath, selfPath := resolvePaths(keyPath, "", "")
	expectedCert := filepath.Join("testdir", "client.pem")
	expectedCSR := filepath.Join("testdir", "csr.pem")
	expectedSelf := filepath.Join("testdir", "self.pem")

	if certPath != expectedCert {
		t.Errorf("got certPath %q, want %q", certPath, expectedCert)
	}
	if csrPath != expectedCSR {
		t.Errorf("got csrPath %q, want %q", csrPath, expectedCSR)
	}
	if selfPath != expectedSelf {
		t.Errorf("got selfPath %q, want %q", selfPath, expectedSelf)
	}

	// Test 2: Custom CSR and Cert paths provided
	customCSR := filepath.Join("testdir", "custom_serverA.csr")
	customCert := filepath.Join("testdir", "custom_serverA.crt")
	certPath, csrPath, selfPath = resolvePaths(keyPath, customCert, customCSR)

	if certPath != customCert {
		t.Errorf("got certPath %q, want %q", certPath, customCert)
	}
	if csrPath != customCSR {
		t.Errorf("got csrPath %q, want %q", csrPath, customCSR)
	}
	if selfPath != expectedSelf {
		t.Errorf("got selfPath %q, want %q", selfPath, expectedSelf)
	}
}

func TestLoadOrMakeCSR_CustomPath(t *testing.T) {
	tmpDir, err := os.MkdirTemp("", "scepclient-csr-test")
	if err != nil {
		t.Fatal(err)
	}
	defer os.RemoveAll(tmpDir)

	keyA, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}

	keyB, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}

	csrPathA := filepath.Join(tmpDir, "serverA_csr.pem")
	csrPathB := filepath.Join(tmpDir, "serverB_csr.pem")

	optsA := &csrOptions{
		cn:  "server-a.example.com",
		org: "Org A",
		key: keyA,
	}

	optsB := &csrOptions{
		cn:  "server-b.example.com",
		org: "Org B",
		key: keyB,
	}

	// Create CSR A at custom path
	reqA, err := loadOrMakeCSR(csrPathA, optsA)
	if err != nil {
		t.Fatalf("failed to create CSR A: %v", err)
	}
	if reqA.Subject.CommonName != "server-a.example.com" {
		t.Errorf("expected CN server-a.example.com, got %s", reqA.Subject.CommonName)
	}

	// Create CSR B in same directory at distinct custom path
	reqB, err := loadOrMakeCSR(csrPathB, optsB)
	if err != nil {
		t.Fatalf("failed to create CSR B: %v", err)
	}
	if reqB.Subject.CommonName != "server-b.example.com" {
		t.Errorf("expected CN server-b.example.com, got %s", reqB.Subject.CommonName)
	}

	// Verify both files exist independently on disk
	if _, err := os.Stat(csrPathA); err != nil {
		t.Errorf("CSR A file missing on disk: %v", err)
	}
	if _, err := os.Stat(csrPathB); err != nil {
		t.Errorf("CSR B file missing on disk: %v", err)
	}

	// Calling loadOrMakeCSR on existing path loads existing file without re-creating
	loadedA, err := loadOrMakeCSR(csrPathA, optsB) // pass optsB to ensure it doesn't overwrite
	if err != nil {
		t.Fatalf("failed to load existing CSR A: %v", err)
	}
	if loadedA.Subject.CommonName != "server-a.example.com" {
		t.Errorf("expected existing CSR CN server-a.example.com, got %s", loadedA.Subject.CommonName)
	}
}
