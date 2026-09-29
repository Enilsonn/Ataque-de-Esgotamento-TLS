package main

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"fmt"
	"math/big"
	"net"
	"os"
	"sync/atomic"
	"time"
)

const (
	host = "127.0.0.1"
	port = "8443"
)

var activeHandshakes int64

func geraCertificadoSeNecessario() (certPEM, keyPEM []byte, err error) {
	certPath, keyPath := "cert.pem", "key.pem"

	if _, errC := os.Stat(certPath); errC == nil {
		if _, errK := os.Stat(keyPath); errK == nil {
			certPEM, _ = os.ReadFile(certPath)
			keyPEM, _ = os.ReadFile(keyPath)
			return certPEM, keyPEM, nil
		}
	}

	priv, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return nil, nil, err
	}

	serialNumber, _ := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 128))

	template := x509.Certificate{
		SerialNumber: serialNumber,
		Subject:      pkix.Name{CommonName: "localhost"},
		NotBefore:    time.Now(),
		NotAfter:     time.Now().Add(365 * 24 * time.Hour),
		KeyUsage:     x509.KeyUsageDigitalSignature,
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		DNSNames:     []string{"localhost"},
	}

	derBytes, err := x509.CreateCertificate(rand.Reader, &template, &template, &priv.PublicKey, priv)
	if err != nil {
		return nil, nil, err
	}

	certPEM = pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: derBytes})

	keyBytes, err := x509.MarshalPKCS8PrivateKey(priv)
	if err != nil {
		return nil, nil, err
	}
	keyPEM = pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: keyBytes})

	_ = os.WriteFile(certPath, certPEM, 0600)
	_ = os.WriteFile(keyPath, keyPEM, 0600)

	fmt.Println("certificado gerado")
	return certPEM, keyPEM, nil
}

func handleClient(rawConn net.Conn, tlsConfig *tls.Config, safeMode bool) {
	addr := rawConn.RemoteAddr()
	n := atomic.AddInt64(&activeHandshakes, 1)

	fmt.Printf("nova conexão de %s, total de %d ativos", addr, n)

	start := time.Now()

	defer func() {
		atomic.AddInt64(&activeHandshakes, -1)
		rawConn.Close()
	}()

	if safeMode {
		// defesa: um timeout agressivo especificamente para o handshake
		rawConn.SetDeadline(time.Now().Add(3 * time.Second))
	}

	tlsConn := tls.Server(rawConn, tlsConfig)
	err := tlsConn.Handshake()
	elapsed := time.Since(start)

	if err != nil {
		fmt.Printf("%s falhou/timeout apos %s (%v)\n", addr, elapsed, err)
		return
	}

	fmt.Printf("handshake completo com %s em %s\n", addr, elapsed)
}
