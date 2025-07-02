package util

import (
	cryptorand "crypto/rand"
	"crypto/x509"
	"encoding/pem"
	"net"
	"strings"
	"time"

	certutil "github.com/rancher/dynamiclistener/cert"
)

// cert usage constants
const (
	CertUsageCertSign   = "CertSign"
	CertUsageServerAuth = "ServerAuth"
	CertUsageClientAuth = "ClientAuth"
	CertUsageUnknown    = "Unknown"
)

// cert status constants
const (
	CertStatusOK          = "OK"
	CertStatusWarning     = "WARNING"
	CertStatusExpired     = "EXPIRED"
	CertStatusNotYetValid = "NOT YET VALID"
)

// EncodeCertsPEM is a wrapper around the EncodeCertPEM function to return the
// PEM encoding of a cert and chain, instead of just a single cert.
func EncodeCertsPEM(cert *x509.Certificate, caCerts []*x509.Certificate) []byte {
	pemBytes := certutil.EncodeCertPEM(cert)
	for _, caCert := range caCerts {
		pemBytes = append(pemBytes, certutil.EncodeCertPEM(caCert)...)
	}
	return pemBytes
}

// GetCertUsages returns a slice of strings representing the certificate usages
func GetCertUsages(cert *x509.Certificate) []string {
	usages := []string{}
	if cert.KeyUsage&x509.KeyUsageCertSign != 0 {
		usages = append(usages, CertUsageCertSign)
	}
	for _, eku := range cert.ExtKeyUsage {
		switch eku {
		case x509.ExtKeyUsageServerAuth:
			usages = append(usages, CertUsageServerAuth)
		case x509.ExtKeyUsageClientAuth:
			usages = append(usages, CertUsageClientAuth)
		}
	}
	if len(usages) == 0 {
		usages = append(usages, CertUsageUnknown)
	}
	return usages
}

// GetCertStatus determines the status of a certificate based on its validity period
func GetCertStatus(cert *x509.Certificate, now time.Time, warn time.Time) string {
	if now.Before(cert.NotBefore) {
		return CertStatusNotYetValid
	} else if now.After(cert.NotAfter) {
		return CertStatusExpired
	} else if warn.After(cert.NotAfter) {
		return CertStatusWarning
	}
	return CertStatusOK
}

func AddSANs(altNames *certutil.AltNames, sans []string) {
	for _, san := range sans {
		ip := net.ParseIP(san)
		if ip == nil {
			altNames.DNSNames = append(altNames.DNSNames, san)
		} else {
			altNames.IPs = append(altNames.IPs, ip)
		}
	}
}

func GetCSRBytes(keyFile string) ([]byte, error) {
	keyBytes, _, err := certutil.LoadOrGenerateKeyFile(keyFile, false)
	if err != nil {
		return nil, err
	}
	key, err := certutil.ParsePrivateKeyPEM(keyBytes)
	if err != nil {
		return nil, err
	}
	return x509.CreateCertificateRequest(cryptorand.Reader, &x509.CertificateRequest{}, key)
}

func SplitCertKeyPEM(bytes []byte) (certPem []byte, keyPem []byte) {
	for {
		b, rest := pem.Decode(bytes)
		if b == nil {
			break
		}
		bytes = rest

		if strings.Contains(b.Type, "PRIVATE KEY") {
			keyPem = append(keyPem, pem.EncodeToMemory(b)...)
		} else {
			certPem = append(certPem, pem.EncodeToMemory(b)...)
		}
	}

	return
}
