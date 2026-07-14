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
	"strings"
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
		CreatedAt:    time.Now().UTC(),
		LastModified: time.Now().UTC(),
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

func (pm *PasswordManager) CheckPasswordStrength(password string) error {
	if len([]rune(password)) < 8 {
		return fmt.Errorf("password is too weak")
	}

	var upperDigits = "ABCDEFGHIGKLMNOPQRSTUVWXYZ"
	var lowDigits = "abcdefghigklmnopqrstuvwxyz"
	var numbers = "1234567890"
	var symbols = "!@#$%^&*()_+~<>?:}{|'/.,;"

	var useUpperDigits, useLowDigits, useNumbers, useSymbols bool

	for _, r := range password {
		if strings.ContainsRune(upperDigits, r) {
			useUpperDigits = true
		}
		if strings.ContainsRune(lowDigits, r) {
			useLowDigits = true
		}
		if strings.ContainsRune(numbers, r) {
			useNumbers = true
		}
		if strings.ContainsRune(symbols, r) {
			useSymbols = true
		}
	}
	if !useUpperDigits || !useLowDigits || !useNumbers || !useSymbols {
		return fmt.Errorf("password don`t have upper digit or low digit or number or symbol")
	}

	return nil
}

func (pm *PasswordManager) GetPasswordsByCategory(category string) []Password {
	var result []Password

	for _, p := range pm.passwords {
		if p.Category == category {
			result = append(result, p)
		}
	}

	return result
}

func (pm *PasswordManager) FindDuplicatePasswords() map[string][]string {
	passwords := make(map[string][]string)
	resultPasswords := make(map[string][]string)

	for _, p := range pm.passwords {
		passwords[p.Value] = append(passwords[p.Value], p.Name)
	}

	for key, value := range passwords {
		if len(value) > 1 {
			resultPasswords[key] = value
		}
	}
	return resultPasswords
}

func (pm *PasswordManager) UpdatePassword(name, newValue string) error {
	if pm.isInitialized == false {
		return fmt.Errorf("password manager not initialized")
	}

	if _, ok := pm.passwords[name]; !ok {
		return fmt.Errorf("password not found")
	}

	if err := pm.CheckPasswordStrength(newValue); err != nil {
		return err
	}

	updatePass := pm.passwords[name]

	updatePass.Value = newValue
	updatePass.LastModified = time.Now().UTC()

	pm.passwords[name] = updatePass

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
