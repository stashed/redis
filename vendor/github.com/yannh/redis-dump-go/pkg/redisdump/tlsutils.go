package redisdump

import (
	"crypto/tls"
	"crypto/x509"
	"errors"
	"fmt"
	"io/ioutil"
)

type TlsHandler struct {
	SkipVerify bool
	CACertPath string
	CertPath   string
	KeyPath    string
}

func NewTlsHandler(caCertPath, certPath, keyPath string, insecure bool) (*TlsHandler, error) {
	if caCertPath == "" && certPath == "" && keyPath == "" {
		if insecure {
			return &TlsHandler{
				SkipVerify: true,
			}, nil
		} else {
			return nil, errors.New("no cert is set. if skip cert validation to set -insecure option")
		}
	}

	return &TlsHandler{
		SkipVerify: false,
		CACertPath: caCertPath,
		CertPath:   certPath,
		KeyPath:    keyPath,
	}, nil
}

func tlsConfig(tlsHandler *TlsHandler) (*tls.Config, error) {
	if tlsHandler == nil {
		return nil, nil
	}

	if tlsHandler.SkipVerify {
		return &tls.Config{
			InsecureSkipVerify: true,
		}, nil
	}

	certPool := x509.NewCertPool()
	// ca cert is optional
	if tlsHandler.CACertPath != "" {
		pem, err := ioutil.ReadFile(tlsHandler.CACertPath)
		if err != nil {
			return nil, fmt.Errorf("connectionpool: unable to open CA certs: %v", err)
		}

		if !certPool.AppendCertsFromPEM(pem) {
			return nil, fmt.Errorf("connectionpool: failed parsing or CA certs")
		}
	}

	tlsCfg := &tls.Config{
		Certificates: []tls.Certificate{},
		RootCAs:      certPool,
	}

	if tlsHandler.CertPath != "" && tlsHandler.KeyPath != "" {
		cert, err := tls.LoadX509KeyPair(tlsHandler.CertPath, tlsHandler.KeyPath)
		if err != nil {
			return nil, err
		}
		tlsCfg.Certificates = append(tlsCfg.Certificates, cert)
	}

	return tlsCfg, nil
}
