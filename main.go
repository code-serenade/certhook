package main

import (
	"bytes"
	"crypto/md5"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"log"
	"net"
	"os"
	"strings"

	"github.com/gin-gonic/gin"
	"golang.org/x/crypto/ssh"
)

type RequestData struct {
	Timestamp int64 `json:"timestamp"`
	Payload   struct {
		CertificateName           string   `json:"certificateName"`
		CertificateDomains        []string `json:"certificateDomains"`
		CertificateCertKey        string   `json:"certificateCertKey"`
		CertificateFullchainCerts string   `json:"certificateFullchainCerts"`
		CertificateExpireAt       int64    `json:"certificateExpireAt"`
	} `json:"payload"`
	Sign string `json:"sign"`
}

type SSHConfig struct {
	User       string `json:"user"`
	PrivateKey string `json:"privateKey"`
	Port       string `json:"port"`
	CertPath   string `json:"certPath"`
	Token      string `json:"token"`
}

var Config map[string]SSHConfig

func handleWebhook(c *gin.Context) {
	if c.Request.Method != "POST" {
		c.JSON(405, gin.H{"error": "Method not allowed"})
		return
	}
	var data RequestData
	if err := c.ShouldBindJSON(&data); err != nil {
		c.JSON(400, gin.H{"error": "Invalid request data"})
		return
	}
	log.Printf("Received data: %+v", data)
	// 获取域名对应的 IP 地址
	for _, domain := range data.Payload.CertificateDomains {
		oldDomain := domain
		token := Config[domain].Token
		if len(token) < 1 {
			token = Config["*"].Token
		}
		expectedSign := generateSign(data.Timestamp, token)
		if data.Sign != expectedSign {
			c.JSON(401, gin.H{"error": "Invalid signature"})
			return
		}
		if strings.Contains(domain, "*") {
			domain = strings.ReplaceAll(domain, "*", "ip")
		}
		ips, err := net.LookupIP(domain)
		if err != nil {
			log.Printf("Error looking up IP for domain %s: %v", domain, err)
			continue
		}
		for _, ip := range ips {
			log.Printf("Domain %s has IP %s", oldDomain, ip)
			sendCertAndReloadNginx(ip.String(), oldDomain, data.Payload.CertificateCertKey, data.Payload.CertificateFullchainCerts)
		}
	}
	c.JSON(200, gin.H{"success": true})
}

func generateSign(timestamp int64, callbackToken string) string {
	strToHash := fmt.Sprintf("%d:%s", timestamp, callbackToken)
	hash := md5.Sum([]byte(strToHash))
	return hex.EncodeToString(hash[:])
}

func sendCertAndReloadNginx(ip, domain, certKey, fullchainCerts string) {
	sshConfig := Config[ip]
	if len(sshConfig.User) < 1 {
		sshConfig = Config[domain]
	}
	if len(sshConfig.User) < 1 {
		sshConfig = Config["*"]
	}
	signer, err := ssh.ParsePrivateKey([]byte(sshConfig.PrivateKey))
	if err != nil {
		log.Fatalf("Failed to parse private key: %v err: %v", sshConfig.PrivateKey, err)
	}
	config := &ssh.ClientConfig{
		User: sshConfig.User,
		Auth: []ssh.AuthMethod{
			ssh.PublicKeys(signer),
		},
		HostKeyCallback: ssh.InsecureIgnoreHostKey(),
	}

	client, err := ssh.Dial("tcp", ip+":"+sshConfig.Port, config)
	if err != nil {
		log.Fatalf("Failed to dial: %v", err)
	}
	defer client.Close()

	err = sshRun(client, "mkdir -p "+sshConfig.CertPath)
	if err != nil {
		log.Fatalf("Failed to mkdir certPath: %v", err)
	}

	var certContent bytes.Buffer
	certContent.WriteString(fullchainCerts)

	err = sshRun(client, fmt.Sprintf("cat > %s <<EOF\n%s\nEOF", sshConfig.CertPath+"/"+domain+".pem", certContent.String()))
	if err != nil {
		log.Fatalf("Failed to send cert: %v", err)
	}

	var keyContent bytes.Buffer
	keyContent.WriteString(certKey)

	err = sshRun(client, fmt.Sprintf("cat > %s <<EOF\n%s\nEOF", sshConfig.CertPath+"/"+domain+".key", keyContent.String()))
	if err != nil {
		log.Fatalf("Failed to send key: %v", err)
	}

	err = sshRun(client, "systemctl reload nginx")
	if err != nil {
		log.Fatalf("Failed to reload nginx: %v", err)
	}

	log.Printf("Successfully sent cert and key to %s and reloaded nginx.", ip)
}

func sshRun(client *ssh.Client, command string) error {
	session, err := client.NewSession()
	if err != nil {
		return err
	}
	defer session.Close()
	session.Stdout = os.Stdout
	session.Stderr = os.Stderr
	return session.Run(command)
}

func initConfig() {
	Config = make(map[string]SSHConfig)
	file, err := os.Open("config.json")
	if err != nil {
		log.Fatal(err)
	}
	defer file.Close()
	decoder := json.NewDecoder(file)
	err = decoder.Decode(&Config)
	if err != nil {
		log.Fatal(err)
	}
}

func main() {
	initConfig()
	gin.SetMode(gin.ReleaseMode)
	router := gin.Default()
	v1 := router.Group("/v1")
	v1.POST("/webhook", handleWebhook)
	log.Println("Listening on :3901...")
	if err := router.Run(":3901"); err != nil {
		log.Fatal(err)
	}
}
