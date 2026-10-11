// Used by t/e2e/client-san.sh: Go's crypto/x509 judges client certificate
// chains as a TLS server would (Verify with ExtKeyUsageClientAuth).
//
//   go run client-san-verify.go DIR
//
// DIR holds root_ca.crt and cases/*.pem (leaf first, then the
// intermediate). Prints "VERSION ..." and per case
// "RESULT <case> go accepted|refused <detail>". Standard library only.
package main

import (
	"crypto/x509"
	"encoding/pem"
	"fmt"
	"os"
	"path/filepath"
	"runtime"
	"sort"
	"strings"
)

func certificates(file string) ([]*x509.Certificate, error) {
	data, err := os.ReadFile(file)
	if err != nil {
		return nil, err
	}
	var out []*x509.Certificate
	for {
		var block *pem.Block
		block, data = pem.Decode(data)
		if block == nil {
			break
		}
		if block.Type != "CERTIFICATE" {
			continue
		}
		c, err := x509.ParseCertificate(block.Bytes)
		if err != nil {
			return nil, fmt.Errorf("parse: %v", err)
		}
		out = append(out, c)
	}
	if len(out) == 0 {
		return nil, fmt.Errorf("no certificate in %s", file)
	}
	return out, nil
}

func oneLine(err error) string {
	return strings.Join(strings.Fields(err.Error()), " ")
}

func main() {
	dir := os.Args[1]
	fmt.Println("VERSION Go", runtime.Version())
	root, err := certificates(filepath.Join(dir, "root_ca.crt"))
	if err != nil {
		fmt.Println("ERROR root:", err)
		os.Exit(1)
	}
	roots := x509.NewCertPool()
	roots.AddCert(root[0])
	files, _ := filepath.Glob(filepath.Join(dir, "cases", "*.pem"))
	sort.Strings(files)
	for _, file := range files {
		name := strings.TrimSuffix(filepath.Base(file), ".pem")
		chain, err := certificates(file)
		if err != nil {
			fmt.Printf("RESULT %s go refused %s\n", name, oneLine(err))
			continue
		}
		intermediates := x509.NewCertPool()
		for _, c := range chain[1:] {
			intermediates.AddCert(c)
		}
		_, err = chain[0].Verify(x509.VerifyOptions{
			Roots:         roots,
			Intermediates: intermediates,
			KeyUsages:     []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth},
		})
		if err != nil {
			fmt.Printf("RESULT %s go refused %s\n", name, oneLine(err))
		} else {
			fmt.Printf("RESULT %s go accepted ok\n", name)
		}
	}
}
