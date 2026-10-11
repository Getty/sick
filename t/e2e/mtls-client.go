// The second client stack of t/e2e/mtls.sh: Go's crypto/tls, which shares
// no code with OpenSSL (curl). One request per case, with the root alone as
// trust anchor for the server and a client certificate (or none).
//
//	go run mtls-client.go <dir>
//
// <dir> holds root_ca.crt and cases, one case per line:
//
//	<case> <url> <cert|-> <key|->
//
// Prints a VERSION line and one line per case:
//
//	RESULT <case> status=<code> body=<first line of the body>
//	RESULT <case> error=<what Go said>
//
// Go sends a configured certificate only when the server's list of
// acceptable CAs names an issuer of its chain
// (tls.CertificateRequestInfo.SupportsCertificate); otherwise it sends none.
package main

import (
	"bufio"
	"crypto/tls"
	"crypto/x509"
	"fmt"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"time"
)

func main() {
	if len(os.Args) != 2 {
		fmt.Println("usage: mtls-client <dir>")
		os.Exit(2)
	}
	dir := os.Args[1]
	fmt.Printf("VERSION %s\n", runtime.Version())

	pem, err := os.ReadFile(filepath.Join(dir, "root_ca.crt"))
	if err != nil {
		fmt.Printf("ERROR reading the root: %v\n", err)
		os.Exit(1)
	}
	roots := x509.NewCertPool()
	if !roots.AppendCertsFromPEM(pem) {
		fmt.Println("ERROR no certificate in the root file")
		os.Exit(1)
	}
	cases, err := os.Open(filepath.Join(dir, "cases"))
	if err != nil {
		fmt.Printf("ERROR reading the cases: %v\n", err)
		os.Exit(1)
	}
	defer cases.Close()
	sc := bufio.NewScanner(cases)
	for sc.Scan() {
		f := strings.Fields(sc.Text())
		if len(f) != 4 {
			continue
		}
		fmt.Println(request(roots, f[0], f[1], f[2], f[3]))
	}
}

func request(roots *x509.CertPool, name, url, cert, key string) string {
	conf := &tls.Config{RootCAs: roots, MinVersion: tls.VersionTLS12}
	if cert != "-" {
		pair, err := tls.LoadX509KeyPair(cert, key)
		if err != nil {
			return fmt.Sprintf("RESULT %s error=loading the client certificate: %v", name, err)
		}
		conf.Certificates = []tls.Certificate{pair}
	}
	client := &http.Client{
		Timeout:   10 * time.Second,
		Transport: &http.Transport{TLSClientConfig: conf, DisableKeepAlives: true},
	}
	resp, err := client.Get(url)
	if err != nil {
		return fmt.Sprintf("RESULT %s error=%s", name, strings.ReplaceAll(err.Error(), "\n", " "))
	}
	defer resp.Body.Close()
	body, _ := io.ReadAll(io.LimitReader(resp.Body, 4096))
	first := ""
	for _, line := range strings.Split(string(body), "\n") {
		if line = strings.TrimSpace(line); line != "" {
			first = line
			break
		}
	}
	return fmt.Sprintf("RESULT %s status=%d body=%s", name, resp.StatusCode, first)
}
