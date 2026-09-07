// Package cryptotool provides everyday cryptography helpers: hashing, secure
// random generation, passphrase-based AES-256-GCM encryption, and RSA keygen /
// OAEP encryption. It depends only on the Go standard library — the PBKDF2 key
// derivation is implemented here on top of crypto/hmac.
package cryptotool

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/hmac"
	"crypto/md5"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha1"
	"crypto/sha256"
	"crypto/sha512"
	"crypto/x509"
	"encoding/base64"
	"encoding/binary"
	"encoding/hex"
	"flag"
	"fmt"
	"hash"
	"io"
	"os"

	"github.com/devarashs/netforge/internal/cli"
)

const (
	magic      = "NFE1" // netforge encryption format v1
	saltLen    = 16
	nonceLen   = 12
	keyLen     = 32      // AES-256
	pbkdf2Iter = 200_000 // PBKDF2-HMAC-SHA256 iterations
)

// Command returns the "crypto" command group.
func Command() *cli.Command {
	return &cli.Command{
		Name:  "crypto",
		Short: "hashing, random, AES/RSA encryption helpers",
		Sub: []*cli.Command{
			hashCmd(),
			randCmd(),
			encryptCmd(),
			decryptCmd(),
			rsaKeygenCmd(),
			rsaEncryptCmd(),
			rsaDecryptCmd(),
		},
	}
}

func newFlagSet(name string) *flag.FlagSet {
	fs := flag.NewFlagSet(name, flag.ContinueOnError)
	fs.SetOutput(os.Stderr)
	return fs
}

// pbkdf2SHA256 derives a key from a password and salt using PBKDF2-HMAC-SHA256.
func pbkdf2SHA256(password, salt []byte, iter, length int) []byte {
	prf := hmac.New(sha256.New, password)
	hLen := prf.Size()
	blocks := (length + hLen - 1) / hLen
	dk := make([]byte, 0, blocks*hLen)
	buf := make([]byte, 4)
	for b := 1; b <= blocks; b++ {
		prf.Reset()
		prf.Write(salt)
		binary.BigEndian.PutUint32(buf, uint32(b))
		prf.Write(buf)
		u := prf.Sum(nil)
		t := make([]byte, len(u))
		copy(t, u)
		for i := 2; i <= iter; i++ {
			prf.Reset()
			prf.Write(u)
			u = prf.Sum(nil)
			for j := range t {
				t[j] ^= u[j]
			}
		}
		dk = append(dk, t...)
	}
	return dk[:length]
}

func newHash(algo string) (hash.Hash, error) {
	switch algo {
	case "md5":
		return md5.New(), nil
	case "sha1":
		return sha1.New(), nil
	case "sha256":
		return sha256.New(), nil
	case "sha384":
		return sha512.New384(), nil
	case "sha512":
		return sha512.New(), nil
	default:
		return nil, fmt.Errorf("unknown algorithm %q (md5, sha1, sha256, sha384, sha512)", algo)
	}
}

func hashCmd() *cli.Command {
	return &cli.Command{
		Name:  "hash",
		Short: "hash a file or stdin",
		Run: func(args []string) error {
			fs := newFlagSet("crypto hash")
			algo := fs.String("algo", "sha256", "md5, sha1, sha256, sha384 or sha512")
			file := fs.String("file", "", "input file (stdin if empty)")
			if err := fs.Parse(args); err != nil {
				return err
			}
			h, err := newHash(*algo)
			if err != nil {
				return err
			}
			in, closeFn, err := openInput(*file)
			if err != nil {
				return err
			}
			defer closeFn()
			if _, err := io.Copy(h, in); err != nil {
				return err
			}
			fmt.Printf("%s  %s\n", hex.EncodeToString(h.Sum(nil)), inputLabel(*file))
			return nil
		},
	}
}

func randCmd() *cli.Command {
	return &cli.Command{
		Name:  "rand",
		Short: "generate cryptographically secure random data",
		Run: func(args []string) error {
			fs := newFlagSet("crypto rand")
			n := fs.Int("bytes", 32, "number of random bytes")
			format := fs.String("format", "hex", "hex, base64 or raw")
			password := fs.Bool("password", false, "emit a URL-safe random password instead")
			if err := fs.Parse(args); err != nil {
				return err
			}
			b := make([]byte, *n)
			if _, err := rand.Read(b); err != nil {
				return err
			}
			switch {
			case *password:
				fmt.Println(base64.RawURLEncoding.EncodeToString(b))
			case *format == "hex":
				fmt.Println(hex.EncodeToString(b))
			case *format == "base64":
				fmt.Println(base64.StdEncoding.EncodeToString(b))
			case *format == "raw":
				os.Stdout.Write(b)
			default:
				return fmt.Errorf("unknown format %q", *format)
			}
			return nil
		},
	}
}

// readPassphrase resolves a passphrase from the flag or the NETFORGE_PASS env var.
func readPassphrase(flagVal string) ([]byte, error) {
	if flagVal != "" {
		return []byte(flagVal), nil
	}
	if env := os.Getenv("NETFORGE_PASS"); env != "" {
		return []byte(env), nil
	}
	return nil, fmt.Errorf("no passphrase: pass -pass or set NETFORGE_PASS")
}

func encryptCmd() *cli.Command {
	return &cli.Command{
		Name:  "encrypt",
		Short: "encrypt a file/stdin with AES-256-GCM (passphrase)",
		Run: func(args []string) error {
			fs := newFlagSet("crypto encrypt")
			in := fs.String("in", "", "input file (stdin if empty)")
			out := fs.String("out", "", "output file (stdout if empty)")
			pass := fs.String("pass", "", "passphrase (or set NETFORGE_PASS)")
			if err := fs.Parse(args); err != nil {
				return err
			}
			passphrase, err := readPassphrase(*pass)
			if err != nil {
				return err
			}
			plaintext, err := readAll(*in)
			if err != nil {
				return err
			}

			salt := make([]byte, saltLen)
			nonce := make([]byte, nonceLen)
			if _, err := rand.Read(salt); err != nil {
				return err
			}
			if _, err := rand.Read(nonce); err != nil {
				return err
			}
			key := pbkdf2SHA256(passphrase, salt, pbkdf2Iter, keyLen)
			gcm, err := newGCM(key)
			if err != nil {
				return err
			}
			ct := gcm.Seal(nil, nonce, plaintext, nil)

			var buf []byte
			buf = append(buf, []byte(magic)...)
			buf = append(buf, salt...)
			buf = append(buf, nonce...)
			buf = append(buf, ct...)
			return writeAll(*out, buf)
		},
	}
}

func decryptCmd() *cli.Command {
	return &cli.Command{
		Name:  "decrypt",
		Short: "decrypt AES-256-GCM data produced by 'crypto encrypt'",
		Run: func(args []string) error {
			fs := newFlagSet("crypto decrypt")
			in := fs.String("in", "", "input file (stdin if empty)")
			out := fs.String("out", "", "output file (stdout if empty)")
			pass := fs.String("pass", "", "passphrase (or set NETFORGE_PASS)")
			if err := fs.Parse(args); err != nil {
				return err
			}
			passphrase, err := readPassphrase(*pass)
			if err != nil {
				return err
			}
			data, err := readAll(*in)
			if err != nil {
				return err
			}
			header := len(magic) + saltLen + nonceLen
			if len(data) < header || string(data[:len(magic)]) != magic {
				return fmt.Errorf("input is not netforge-encrypted data")
			}
			salt := data[len(magic) : len(magic)+saltLen]
			nonce := data[len(magic)+saltLen : header]
			ct := data[header:]
			key := pbkdf2SHA256(passphrase, salt, pbkdf2Iter, keyLen)
			gcm, err := newGCM(key)
			if err != nil {
				return err
			}
			pt, err := gcm.Open(nil, nonce, ct, nil)
			if err != nil {
				return fmt.Errorf("decryption failed: wrong passphrase or corrupted data")
			}
			return writeAll(*out, pt)
		},
	}
}

func newGCM(key []byte) (cipher.AEAD, error) {
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}
	return cipher.NewGCM(block)
}

func rsaKeygenCmd() *cli.Command {
	return &cli.Command{
		Name:  "rsa-keygen",
		Short: "generate an RSA keypair (PEM)",
		Run: func(args []string) error {
			fs := newFlagSet("crypto rsa-keygen")
			bits := fs.Int("bits", 3072, "key size in bits")
			out := fs.String("out", "id_rsa", "output basename (writes <out>.pem and <out>.pub.pem)")
			if err := fs.Parse(args); err != nil {
				return err
			}
			key, err := rsa.GenerateKey(rand.Reader, *bits)
			if err != nil {
				return err
			}
			privDER, err := x509.MarshalPKCS8PrivateKey(key)
			if err != nil {
				return err
			}
			if err := writePEMFile(*out+".pem", "PRIVATE KEY", privDER, 0o600); err != nil {
				return err
			}
			pubDER, err := x509.MarshalPKIXPublicKey(&key.PublicKey)
			if err != nil {
				return err
			}
			if err := writePEMFile(*out+".pub.pem", "PUBLIC KEY", pubDER, 0o644); err != nil {
				return err
			}
			fmt.Printf("wrote private key %s.pem and public key %s.pub.pem\n", *out, *out)
			return nil
		},
	}
}

func rsaEncryptCmd() *cli.Command {
	return &cli.Command{
		Name:  "rsa-encrypt",
		Short: "encrypt a small message with an RSA public key (OAEP)",
		Run: func(args []string) error {
			fs := newFlagSet("crypto rsa-encrypt")
			pubFile := fs.String("pub", "", "RSA public key PEM (required)")
			in := fs.String("in", "", "input file (stdin if empty)")
			out := fs.String("out", "", "output file, base64 (stdout if empty)")
			if err := fs.Parse(args); err != nil {
				return err
			}
			pub, err := loadRSAPublic(*pubFile)
			if err != nil {
				return err
			}
			msg, err := readAll(*in)
			if err != nil {
				return err
			}
			ct, err := rsa.EncryptOAEP(sha256.New(), rand.Reader, pub, msg, nil)
			if err != nil {
				return err
			}
			return writeAll(*out, []byte(base64.StdEncoding.EncodeToString(ct)+"\n"))
		},
	}
}

func rsaDecryptCmd() *cli.Command {
	return &cli.Command{
		Name:  "rsa-decrypt",
		Short: "decrypt an RSA-OAEP message with a private key",
		Run: func(args []string) error {
			fs := newFlagSet("crypto rsa-decrypt")
			privFile := fs.String("priv", "", "RSA private key PEM (required)")
			in := fs.String("in", "", "base64 input file (stdin if empty)")
			out := fs.String("out", "", "output file (stdout if empty)")
			if err := fs.Parse(args); err != nil {
				return err
			}
			priv, err := loadRSAPrivate(*privFile)
			if err != nil {
				return err
			}
			raw, err := readAll(*in)
			if err != nil {
				return err
			}
			ct, err := base64.StdEncoding.DecodeString(trimSpace(raw))
			if err != nil {
				return fmt.Errorf("input is not valid base64: %w", err)
			}
			pt, err := rsa.DecryptOAEP(sha256.New(), rand.Reader, priv, ct, nil)
			if err != nil {
				return err
			}
			return writeAll(*out, pt)
		},
	}
}
