package main

import (
	"bytes"
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"encoding/json"
	"fmt"
	"io"
	"os"
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
		return fmt.Errorf("password is too weak")
	}

	keyBuffer := make([]byte, 32)
	copy(keyBuffer, masterPassword)

	pm.masterKey = keyBuffer
	pm.isInitialized = true

	return nil
}

func (pm *PasswordManager) SavePassword(name, value, category string) error {
	if pm.isInitialized == false {
		return fmt.Errorf("password manager not initialized")
	}

	if _, ok := pm.passwords[name]; ok == true {
		return fmt.Errorf("password already exists")
	}

	password := NewPassword(name, value, category)

	pm.passwords[name] = password

	return nil
}

func (pm *PasswordManager) GetPassword(name string) (Password, error) {
	if pm.isInitialized == false {
		return Password{}, fmt.Errorf("password manager not initialized")
	}

	if _, exist := pm.passwords[name]; exist == false {
		return Password{}, fmt.Errorf("password not found")
	}

	return pm.passwords[name], nil
}

func (pm *PasswordManager) ListPasswords() []Password {
	var listPasswords []Password

	for name := range pm.passwords {
		listPasswords = append(listPasswords, pm.passwords[name])
	}

	if len(listPasswords) == 0 {
		return []Password{}
	}

	return listPasswords
}

func (pm *PasswordManager) GeneratePassword(length int) (string, error) {
	if length < 8 {
		return "", fmt.Errorf("password is too weak")
	}

	passwordCharacters := "abcdefghigklmnopqrstuvwxyzABCDEFGHIGKLMNOPQRSTUVWXYZ1234567890!@#$%^&*()_+~<>?:}{|'/.,;'"
	passwordBuffer := make([]byte, length)
	_, err := rand.Read(passwordBuffer)
	if err != nil {
		return "", err
	}

	var resultBuffer bytes.Buffer
	for _, b := range passwordBuffer {
		index := int(b) % len(passwordCharacters)
		resultBuffer.WriteString(string([]rune(passwordCharacters)[index]))
	}

	return resultBuffer.String(), nil
}

func (pm *PasswordManager) SaveToFile() error {
	if pm.isInitialized == false {
		return fmt.Errorf("password manager not initialized")
	}

	passwords, err := json.Marshal(pm.passwords)
	if err != nil {
		return err
	}

	block, err := aes.NewCipher(pm.masterKey)
	if err != nil {
		return fmt.Errorf("cipher block not created")
	}

	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return fmt.Errorf("gcm not created")
	}
	nonceSize := gcm.NonceSize()
	bufferPassword := make([]byte, nonceSize)

	_, err = io.ReadFull(rand.Reader, bufferPassword)
	if err != nil {
		return err
	}
	gsmSeal := gcm.Seal(nil, bufferPassword, passwords, nil)

	file, err := os.Create(pm.filePath)
	if err != nil {
		return err
	}
	defer file.Close()

	_, err = file.Write(bufferPassword)
	if err != nil {
		return err
	}
	_, err = file.Write(gsmSeal)
	if err != nil {
		return err
	}

	return nil
}

func (pm *PasswordManager) LoadFromFile() error {
	if pm.isInitialized == false {
		return fmt.Errorf("password manager not initialized")
	}

	file, err := os.Open(pm.filePath)
	if err != nil {
		return err
	}
	defer file.Close()

	block, err := aes.NewCipher(pm.masterKey)
	if err != nil {
		return fmt.Errorf("cipher block not created")
	}

	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return fmt.Errorf("gcm not created")
	}

	nonceSize := gcm.NonceSize()
	bufferPassword := make([]byte, nonceSize)

	_, err = io.ReadFull(file, bufferPassword)
	if err != nil {
		return err
	}

	authData, err := io.ReadAll(file)
	if err != nil {
		return err
	}

	gcmOpen, err := gcm.Open(nil, bufferPassword, authData, nil)
	if err != nil {
		return err
	}

	err = json.Unmarshal(gcmOpen, &pm.passwords)
	if err != nil {
		return err
	}

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
