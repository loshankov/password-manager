package main

import "time"

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
	Passwords     map[string]Password `json:"passwords"`
	masterKey     []byte
	filePath      string
	isInitialized bool
}

func NewPasswordManager(filePath string) *PasswordManager {
	return &PasswordManager{
		Passwords: make(map[string]Password),
		filePath:  filePath,
	}
}

func main() {

}
