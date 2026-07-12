package main

import (
	"fmt"
	"time"
)

type Password struct {
	Name         string    `json:"name"`
	Value        string    `json:"value"`
	Category     string    `json:"category"`
	CreatedAt    time.Time `json:"createdAt"`
	LastModified time.Time `json:"lastModified"`
}

func NewPassword(name, value, category string) Password {
	return Password{
		Name:         name,
		Value:        value,
		Category:     category,
		CreatedAt:    time.Now(),
		LastModified: time.Now(),
	}
}

type PasswordManager struct {
	passwords     map[string]Password `json:"passwords"`
	masterKey     []byte              `json:"-"`
	filePath      string              `json:"-"`
	isInitialized bool                `json:"-"`
}

func (pm *PasswordManager) SetMasterPassword(masterPassword string) error {
	if len([]rune(masterPassword)) < 8 {
		return fmt.Errorf("password is too week")
	}

	keyBuffer := make([]byte, 32)
	copy(keyBuffer, masterPassword)

	pm.masterKey = keyBuffer
	pm.isInitialized = true

	return nil
}

func NewPasswordManager(filePath string) *PasswordManager {
	return &PasswordManager{
		passwords: make(map[string]Password),
		filePath:  filePath,
	}
}

func main() {

}
