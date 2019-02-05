// Package drac contains the functions to establish an SSH connection with
// a DRAC, using a username/password pair, and implements some utility
// functions to:
// - Reboot the node
// - Disable/Enable IP block for remote access
package drac

import (
	"fmt"
	"io/ioutil"
	"log"

	"golang.org/x/crypto/ssh"
)

// Connection represents a connection to a DRAC. It includes hostname, port,
// credentials and it wraps a ssh.ClientConfig containing authentication
// settings.
type Connection struct {
	Host string
	Port int32
	Auth *ssh.ClientConfig
}

func NewConnection(host string, port int32, username string, password string, privateKeyPath string) *Connection {

	privateBytes, err := ioutil.ReadFile(privateKeyPath)

	if err != nil {
		log.Fatal("Cannot read private key")
	}

	privateKey, err := ssh.ParsePrivateKey(privateBytes)
	privateKeyAuth := ssh.PublicKeys(privateKey)

	if err != nil {
		log.Fatal("Cannot parse private key")
	}

	passwordAuth := ssh.Password(password)

	// TODO: find out how to enable host key verification for M-Lab hosts.
	clientConfig := &ssh.ClientConfig{
		User:            username,
		Auth:            []ssh.AuthMethod{passwordAuth, privateKeyAuth},
		HostKeyCallback: ssh.InsecureIgnoreHostKey(),
	}

	conn := &Connection{
		Host: host,
		Port: port,
		Auth: clientConfig,
	}

	return conn
}

// startSession starts an SSH session on Host:Port, using the provided
// credentials.
func (c *Connection) startSession() (*ssh.Session, error) {
	conn, err := ssh.Dial("tcp", fmt.Sprintf("%s:%d", c.Host, c.Port), c.Auth)

	if err != nil {
		return nil, err
	}

	session, err := conn.NewSession()

	if err != nil {
		return nil, err
	}

	return session, nil
}

// exec runs a command on the specified host, after getting a session.
func (c *Connection) Exec(cmd string) (string, error) {
	log.Printf("DEBUG: exec %s on %s", cmd, c.Host)
	session, err := c.startSession()

	if err != nil {
		log.Printf("Command execution failed: %s\n", err)
	}
	defer session.Close()

	out, _ := session.Output(cmd)

	return string(out), nil
}
