// Package certtool generates and inspects X.509 certificates: self-signed CAs,
// leaf/server certificates (self-signed or CA-signed), across RSA, ECDSA and
// Ed25519 keys.
package certtool

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"flag"
	"fmt"
	"math/big"
	"net"
	"os"
	"strings"
	"time"

	"github.com/devarashs/netforge/internal/cli"
)

// Command returns the "cert" command group.
func Command() *cli.Command {
	return &cli.Command{
		Name:  "cert",
		Short: "generate and inspect X.509 certificates",
		Sub: []*cli.Command{
			caCmd(),
			serverCmd(),
			inspectCmd(),
		},
	}
}

func newFlagSet(name string) *flag.FlagSet {
	fs := flag.NewFlagSet(name, flag.ContinueOnError)
	fs.SetOutput(os.Stderr)
	return fs
}

// generateKey returns a private key of the requested type along with its
// signer public key.
func generateKey(kind string) (crypto.PrivateKey, crypto.PublicKey, error) {
	switch strings.ToLower(kind) {
	case "rsa", "rsa2048":
		k, err := rsa.GenerateKey(rand.Reader, 2048)
		return k, &k.PublicKey, err
	case "rsa4096":
		k, err := rsa.GenerateKey(rand.Reader, 4096)
		return k, &k.PublicKey, err
	case "ecdsa", "p256":
		k, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
		return k, &k.PublicKey, err
	case "p384":
		k, err := ecdsa.GenerateKey(elliptic.P384(), rand.Reader)
		return k, &k.PublicKey, err
	case "ed25519":
		pub, priv, err := ed25519.GenerateKey(rand.Reader)
		return priv, pub, err
	default:
		return nil, nil, fmt.Errorf("unknown key type %q (use rsa, rsa4096, ecdsa, p384 or ed25519)", kind)
	}
}

func serialNumber() (*big.Int, error) {
	limit := new(big.Int).Lsh(big.NewInt(1), 128)
	return rand.Int(rand.Reader, limit)
}

// writePEM writes a single PEM block to path with the given permission.
func writePEM(path, blockType string, der []byte, perm os.FileMode) error {
	f, err := os.OpenFile(path, os.O_WRONLY|os.O_CREATE|os.O_TRUNC, perm)
	if err != nil {
		return err
	}
	defer f.Close()
	return pem.Encode(f, &pem.Block{Type: blockType, Bytes: der})
}

func writeKey(path string, key crypto.PrivateKey) error {
	der, err := x509.MarshalPKCS8PrivateKey(key)
	if err != nil {
		return err
	}
	return writePEM(path, "PRIVATE KEY", der, 0o600)
}

func parseHosts(dns, ips string) ([]string, []net.IP) {
	var names []string
	var addrs []net.IP
	for _, d := range strings.Split(dns, ",") {
		if d = strings.TrimSpace(d); d != "" {
			names = append(names, d)
		}
	}
	for _, s := range strings.Split(ips, ",") {
		if s = strings.TrimSpace(s); s != "" {
			if ip := net.ParseIP(s); ip != nil {
				addrs = append(addrs, ip)
			}
		}
	}
	return names, addrs
}

func caCmd() *cli.Command {
	return &cli.Command{
		Name:  "ca",
		Short: "generate a self-signed certificate authority",
		Run: func(args []string) error {
			fs := newFlagSet("cert ca")
			cn := fs.String("cn", "netforge local CA", "common name")
			org := fs.String("org", "netforge", "organization")
			keyType := fs.String("key-type", "ecdsa", "rsa, rsa4096, ecdsa, p384 or ed25519")
			days := fs.Int("days", 3650, "validity period in days")
			out := fs.String("out", "ca", "output basename (writes <out>.pem and <out>.key)")
			if err := fs.Parse(args); err != nil {
				return err
			}

			priv, pub, err := generateKey(*keyType)
			if err != nil {
				return err
			}
			serial, err := serialNumber()
			if err != nil {
				return err
			}
			tmpl := &x509.Certificate{
				SerialNumber:          serial,
				Subject:               pkix.Name{CommonName: *cn, Organization: []string{*org}},
				NotBefore:             time.Now().Add(-time.Hour),
				NotAfter:              time.Now().AddDate(0, 0, *days),
				KeyUsage:              x509.KeyUsageCertSign | x509.KeyUsageCRLSign | x509.KeyUsageDigitalSignature,
				BasicConstraintsValid: true,
				IsCA:                  true,
				MaxPathLenZero:        true,
			}
			der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, pub, priv)
			if err != nil {
				return err
			}
			if err := writePEM(*out+".pem", "CERTIFICATE", der, 0o644); err != nil {
				return err
			}
			if err := writeKey(*out+".key", priv); err != nil {
				return err
			}
			fmt.Printf("wrote CA certificate %s.pem and private key %s.key\n", *out, *out)
			return nil
		},
	}
}

func serverCmd() *cli.Command {
	return &cli.Command{
		Name:  "server",
		Short: "generate a leaf/server cert (self-signed, or signed by a CA)",
		Run: func(args []string) error {
			fs := newFlagSet("cert server")
			cn := fs.String("cn", "localhost", "common name")
			org := fs.String("org", "netforge", "organization")
			dns := fs.String("dns", "localhost", "comma-separated DNS SANs")
			ips := fs.String("ip", "127.0.0.1,::1", "comma-separated IP SANs")
			keyType := fs.String("key-type", "ecdsa", "rsa, rsa4096, ecdsa, p384 or ed25519")
			days := fs.Int("days", 825, "validity period in days")
			out := fs.String("out", "server", "output basename (writes <out>.pem and <out>.key)")
			caCert := fs.String("ca-cert", "", "CA certificate PEM to sign with (self-signed if empty)")
			caKey := fs.String("ca-key", "", "CA private key PEM (required with -ca-cert)")
			if err := fs.Parse(args); err != nil {
				return err
			}

			priv, pub, err := generateKey(*keyType)
			if err != nil {
				return err
			}
			serial, err := serialNumber()
			if err != nil {
				return err
			}
			names, addrs := parseHosts(*dns, *ips)
			tmpl := &x509.Certificate{
				SerialNumber: serial,
				Subject:      pkix.Name{CommonName: *cn, Organization: []string{*org}},
				NotBefore:    time.Now().Add(-time.Hour),
				NotAfter:     time.Now().AddDate(0, 0, *days),
				KeyUsage:     x509.KeyUsageDigitalSignature | x509.KeyUsageKeyEncipherment,
				ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth, x509.ExtKeyUsageClientAuth},
				DNSNames:     names,
				IPAddresses:  addrs,
			}

			parent := tmpl
			var signerKey crypto.PrivateKey = priv
			if *caCert != "" || *caKey != "" {
				if *caCert == "" || *caKey == "" {
					return fmt.Errorf("-ca-cert and -ca-key must be provided together")
				}
				ca, key, err := loadCA(*caCert, *caKey)
				if err != nil {
					return err
				}
				parent = ca
				signerKey = key
			}

			der, err := x509.CreateCertificate(rand.Reader, tmpl, parent, pub, signerKey)
			if err != nil {
				return err
			}
			if err := writePEM(*out+".pem", "CERTIFICATE", der, 0o644); err != nil {
				return err
			}
			if err := writeKey(*out+".key", priv); err != nil {
				return err
			}
			signedBy := "self-signed"
			if *caCert != "" {
				signedBy = "signed by " + *caCert
			}
			fmt.Printf("wrote %s certificate %s.pem and private key %s.key (%s)\n", signedBy, *out, *out, *keyType)
			return nil
		},
	}
}

func loadCA(certPath, keyPath string) (*x509.Certificate, crypto.PrivateKey, error) {
	certPEM, err := os.ReadFile(certPath)
	if err != nil {
		return nil, nil, err
	}
	block, _ := pem.Decode(certPEM)
	if block == nil {
		return nil, nil, fmt.Errorf("no PEM block in %s", certPath)
	}
	cert, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		return nil, nil, err
	}
	keyPEM, err := os.ReadFile(keyPath)
	if err != nil {
		return nil, nil, err
	}
	kb, _ := pem.Decode(keyPEM)
	if kb == nil {
		return nil, nil, fmt.Errorf("no PEM block in %s", keyPath)
	}
	key, err := x509.ParsePKCS8PrivateKey(kb.Bytes)
	if err != nil {
		return nil, nil, err
	}
	return cert, key, nil
}

func inspectCmd() *cli.Command {
	return &cli.Command{
		Name:  "inspect",
		Short: "print details of a certificate PEM file",
		Run: func(args []string) error {
			fs := newFlagSet("cert inspect")
			file := fs.String("file", "", "certificate PEM file (required)")
			if err := fs.Parse(args); err != nil {
				return err
			}
			if *file == "" {
				fs.Usage()
				return fmt.Errorf("-file is required")
			}
			data, err := os.ReadFile(*file)
			if err != nil {
				return err
			}
			block, _ := pem.Decode(data)
			if block == nil {
				return fmt.Errorf("no PEM block in %s", *file)
			}
			c, err := x509.ParseCertificate(block.Bytes)
			if err != nil {
				return err
			}
			fmt.Printf("Subject:      %s\n", c.Subject)
			fmt.Printf("Issuer:       %s\n", c.Issuer)
			fmt.Printf("Serial:       %s\n", c.SerialNumber)
			fmt.Printf("Not before:   %s\n", c.NotBefore.Format(time.RFC3339))
			fmt.Printf("Not after:    %s\n", c.NotAfter.Format(time.RFC3339))
			fmt.Printf("Is CA:        %t\n", c.IsCA)
			fmt.Printf("Key algo:     %s\n", c.PublicKeyAlgorithm)
			fmt.Printf("Sig algo:     %s\n", c.SignatureAlgorithm)
			if len(c.DNSNames) > 0 {
				fmt.Printf("DNS SANs:     %s\n", strings.Join(c.DNSNames, ", "))
			}
			if len(c.IPAddresses) > 0 {
				ips := make([]string, len(c.IPAddresses))
				for i, ip := range c.IPAddresses {
					ips[i] = ip.String()
				}
				fmt.Printf("IP SANs:      %s\n", strings.Join(ips, ", "))
			}
			remaining := time.Until(c.NotAfter)
			fmt.Printf("Expires in:   %d days\n", int(remaining.Hours()/24))
			return nil
		},
	}
}
