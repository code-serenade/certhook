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
	"time"

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
	User       string   `json:"user"`
	PrivateKey string   `json:"privateKey"`
	Port       string   `json:"port"`
	CertPath   string   `json:"certPath"`
	Token      string   `json:"token"`
	IPS        []IPInfo `json:"ips"`
}

type IPInfo struct {
	IP   string `json:"ip"`
	Port string `json:"port"`
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
	unknown := false
	for _, domain := range data.Payload.CertificateDomains {
		oldDomain := domain
		sshConfig := Config[domain]
		token := sshConfig.Token
		if len(token) < 1 {
			sshConfig = Config["*"]
			token = sshConfig.Token
		}
		expectedSign := generateSign(data.Timestamp, token)
		if data.Sign != expectedSign {
			c.JSON(401, gin.H{"error": "Invalid signature"})
			return
		}
		if len(sshConfig.IPS) > 0 {
			err := sendCertAndReloadNginx("", oldDomain, data.Payload.CertificateCertKey, data.Payload.CertificateFullchainCerts)
			if err != nil {
				c.JSON(401, gin.H{"error": err.Error()})
				return
			}
		} else {
			if strings.Contains(domain, "*") {
				domain = strings.ReplaceAll(domain, "*", "ip")
			}
			ips, err := net.LookupIP(domain)
			if err != nil {
				log.Printf("Error looking up IP for domain %s: %v", domain, err)
				unknown = true
				break
			}
			for _, ip := range ips {
				log.Printf("Domain %s has IP %s", oldDomain, ip)
				err = sendCertAndReloadNginx(ip.String(), oldDomain, data.Payload.CertificateCertKey, data.Payload.CertificateFullchainCerts)
				if err != nil {
					c.JSON(401, gin.H{"error": err.Error()})
					return
				}
			}
		}

	}
	if unknown {
		c.JSON(401, gin.H{"error": "Unknown domain"})
		return
	}
	c.JSON(200, gin.H{"success": true})
}

func generateSign(timestamp int64, callbackToken string) string {
	strToHash := fmt.Sprintf("%d:%s", timestamp, callbackToken)
	hash := md5.Sum([]byte(strToHash))
	return hex.EncodeToString(hash[:])
}

func sendCertAndReloadNginx(ip, domain, certKey, fullchainCerts string) (err error) {
	sshConfig := Config[ip]
	if len(sshConfig.User) < 1 {
		sshConfig = Config[domain]
	}
	if len(sshConfig.User) < 1 {
		sshConfig = Config["*"]
	}
	if len(sshConfig.IPS) > 0 {
		for _, ipInfo := range sshConfig.IPS {
			err = sendCertAndReloadNginxSingle(ipInfo.IP, ipInfo.Port, domain, certKey, fullchainCerts, sshConfig)
			if err != nil {
				return
			}
		}
	} else {
		err = sendCertAndReloadNginxSingle(ip, sshConfig.Port, domain, certKey, fullchainCerts, sshConfig)
		if err != nil {
			return
		}
	}

	return
}

func sendCertAndReloadNginxSingle(ip, port, domain, certKey, fullchainCerts string, sshConfig SSHConfig) (err error) {
	signer, err := ssh.ParsePrivateKey([]byte(sshConfig.PrivateKey))
	if err != nil {
		log.Printf("Failed to parse private key: %v err: %v\n", sshConfig.PrivateKey, err)
		return
	}
	config := &ssh.ClientConfig{
		User: sshConfig.User,
		Auth: []ssh.AuthMethod{
			ssh.PublicKeys(signer),
		},
		HostKeyCallback: ssh.InsecureIgnoreHostKey(),
		Timeout:         time.Second * 10,
	}

	client, err := ssh.Dial("tcp", ip+":"+port, config)
	if err != nil {
		log.Printf("Failed to dial: %v\n", err)
		return
	}
	defer client.Close()

	err = sshRun(client, "mkdir -p "+sshConfig.CertPath)
	if err != nil {
		log.Printf("Failed to mkdir certPath: %v\n", err)
		return
	}

	var certContent bytes.Buffer
	certContent.WriteString(fullchainCerts)

	err = sshRun(client, fmt.Sprintf("cat > %s <<EOF\n%s\nEOF", sshConfig.CertPath+"/"+domain+".pem", certContent.String()))
	if err != nil {
		log.Printf("Failed to send cert: %v\n", err)
		return
	}

	var keyContent bytes.Buffer
	keyContent.WriteString(certKey)

	err = sshRun(client, fmt.Sprintf("cat > %s <<EOF\n%s\nEOF", sshConfig.CertPath+"/"+domain+".key", keyContent.String()))
	if err != nil {
		log.Printf("Failed to send key: %v\n", err)
		return
	}

	err = sshRun(client, "nginx -t")
	if err != nil {
		log.Printf("Failed to nginx -t: %v\n", err)
		return
	}

	err = sshRun(client, "systemctl reload nginx")
	if err != nil {
		log.Printf("Failed to reload nginx: %v\n", err)
		return
	}

	log.Printf("Successfully sent cert and key to %s and reloaded nginx.\n", ip)
	return
}

func sshRun(client *ssh.Client, command string) (err error) {
	session, err := client.NewSession()
	if err != nil {
		return
	}
	defer session.Close()
	var stdout, stderr bytes.Buffer
	session.Stdout = &stdout
	session.Stderr = &stderr
	err = session.Run(command)
	if err != nil {
		log.Printf("Command '%s' failed with error: %v\nStderr: %s", command, err, stderr.String())
	} else {
		log.Printf("Command '%s' executed successfully.\nStdout: %s", command, stdout.String())
	}
	return
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
