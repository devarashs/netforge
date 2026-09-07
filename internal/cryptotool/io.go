package cryptotool

import (
	"crypto/rsa"
	"crypto/x509"
	"encoding/pem"
	"fmt"
	"io"
	"os"
	"strings"
)

// openInput returns a reader for path, or stdin when path is empty.
func openInput(path string) (io.Reader, func(), error) {
	if path == "" {
		return os.Stdin, func() {}, nil
	}
	f, err := os.Open(path)
	if err != nil {
		return nil, nil, err
	}
	return f, func() { f.Close() }, nil
}

func inputLabel(path string) string {
	if path == "" {
		return "-"
	}
	return path
}

// readAll reads the entire contents of path, or stdin when path is empty.
func readAll(path string) ([]byte, error) {
	if path == "" {
		return io.ReadAll(os.Stdin)
	}
	return os.ReadFile(path)
}

// writeAll writes data to path, or stdout when path is empty.
func writeAll(path string, data []byte) error {
	if path == "" {
		_, err := os.Stdout.Write(data)
		return err
	}
	return os.WriteFile(path, data, 0o600)
}

func writePEMFile(path, blockType string, der []byte, perm os.FileMode) error {
	f, err := os.OpenFile(path, os.O_WRONLY|os.O_CREATE|os.O_TRUNC, perm)
	if err != nil {
		return err
	}
	defer f.Close()
	return pem.Encode(f, &pem.Block{Type: blockType, Bytes: der})
}

func trimSpace(b []byte) string { return strings.TrimSpace(string(b)) }

func loadRSAPublic(path string) (*rsa.PublicKey, error) {
	if path == "" {
		return nil, fmt.Errorf("-pub is required")
	}
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	block, _ := pem.Decode(data)
	if block == nil {
		return nil, fmt.Errorf("no PEM block in %s", path)
	}
	pub, err := x509.ParsePKIXPublicKey(block.Bytes)
	if err != nil {
		return nil, err
	}
	rp, ok := pub.(*rsa.PublicKey)
	if !ok {
		return nil, fmt.Errorf("%s is not an RSA public key", path)
	}
	return rp, nil
}

func loadRSAPrivate(path string) (*rsa.PrivateKey, error) {
	if path == "" {
		return nil, fmt.Errorf("-priv is required")
	}
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	block, _ := pem.Decode(data)
	if block == nil {
		return nil, fmt.Errorf("no PEM block in %s", path)
	}
	key, err := x509.ParsePKCS8PrivateKey(block.Bytes)
	if err != nil {
		// fall back to PKCS#1
		if k, e2 := x509.ParsePKCS1PrivateKey(block.Bytes); e2 == nil {
			return k, nil
		}
		return nil, err
	}
	rp, ok := key.(*rsa.PrivateKey)
	if !ok {
		return nil, fmt.Errorf("%s is not an RSA private key", path)
	}
	return rp, nil
}
