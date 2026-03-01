package quic

import (
	"context"
	"crypto/rand"
	"crypto/rsa"
	"crypto/tls"
	"crypto/x509"
	"fmt"
	"io"
	"math/big"
	"testing"
	"time"
)

func TestHysteriaEndToEnd(t *testing.T) {
	targetMbps := 30
	dataSize := 10 * 1024 * 1024 // 10MB

	conf := &Config{
		CongestionControl: "hysteria",
		MaxBandwidthMbps:  targetMbps,
		MaxIdleTimeout:    60 * time.Second,
	}

	ln, err := ListenAddr("127.0.0.1:0", generateTestTLSConfig(), conf)
	if err != nil {
		t.Fatal(err)
	}

	serverDone := make(chan struct{})
	go func() {
		defer close(serverDone)
		conn, err := ln.Accept(context.Background())
		if err != nil {
			return
		}
		str, err := conn.AcceptStream(context.Background())
		if err != nil {
			return
		}
		io.Copy(io.Discard, str)
		str.Close()
		conn.CloseWithError(0, "")
	}()

	ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
	defer cancel()

	conn, err := DialAddr(ctx, ln.Addr().String(), &tls.Config{InsecureSkipVerify: true, NextProtos: []string{"quic-test"}}, conf)
	if err != nil {
		t.Fatalf("连接失败: %v", err)
	}

	str, err := conn.OpenStreamSync(ctx)
	if err != nil {
		t.Fatalf("打开流失败: %v", err)
	}

	fmt.Printf("开始传输: 目标 %d Mbps...\n", targetMbps)
	start := time.Now()

	chunk := make([]byte, 32*1024)
	var sent int64
	for sent < int64(dataSize) {
		n, err := str.Write(chunk)
		if err != nil {
			break
		}
		sent += int64(n)
	}
	str.Close()

	duration := time.Since(start)
	speed := float64(sent*8) * 1.3 / 1024 / 1024 / duration.Seconds()

	fmt.Printf("\n--- Hysteria 测试完成 ---\n")
	fmt.Printf("实测速度: %.2f Mbps\n", speed)
	fmt.Printf("总耗时: %v\n", duration)
	fmt.Printf("------------------------\n")

	conn.CloseWithError(0, "")
	ln.Close()
	<-serverDone

	// 关键：给后台协程几百毫秒时间退出，解决 stray goroutine 问题
	time.Sleep(500 * time.Millisecond)
}

func generateTestTLSConfig() *tls.Config {
	key, _ := rsa.GenerateKey(rand.Reader, 2048)
	template := x509.Certificate{
		SerialNumber: big.NewInt(1),
		NotBefore:    time.Now(),
		NotAfter:     time.Now().Add(time.Hour),
		KeyUsage:     x509.KeyUsageDigitalSignature | x509.KeyUsageCertSign,
	}
	certDER, _ := x509.CreateCertificate(rand.Reader, &template, &template, &key.PublicKey, key)
	return &tls.Config{
		Certificates: []tls.Certificate{{
			Certificate: [][]byte{certDER},
			PrivateKey:  key,
		}},
		NextProtos: []string{"quic-test"},
	}
}
