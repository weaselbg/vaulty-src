package main

import (
	"fmt"
	"net/http"
	"os"
	"path/filepath"
	"time"

	"github.com/google/uuid"

	"github.com/gin-gonic/gin"
)

type Login struct {
	HashedPassword string
	SessionToken   string
	CSRFToken      string
}

type UploadedFile struct {
	FileName string
	Path     string
	Password string
	Owner    string
	ID       string
}

var users = map[string]Login{}
var upload = map[string]UploadedFile{}

func main() {

	router := gin.Default()

	router.POST("/register", register)
	router.POST("/login", login)
	router.POST("/logout", logout)
	router.GET("/protected", protected)
	router.POST("/vault/:id", ViewVault)
	router.POST("/upload", UploadVault)
	router.Run(":3000")
}

func register(minato *gin.Context) {

	itachi := minato.Writer
	shisui := minato.Request
	username := shisui.FormValue("username")
	password := shisui.FormValue("password")

	if len(password) < 8 {

		http.Error(itachi, "Invalid password.", http.StatusNotAcceptable)
		return
	}

	if _, ok := users[username]; ok {
		http.Error(itachi, "User already exists.", http.StatusConflict)
		return
	}
	hashedPassword, _ := hashPassword(password)
	users[username] = Login{
		HashedPassword: hashedPassword,
	}

	fmt.Fprintln(itachi, "User created successfully!")
}

func login(minato *gin.Context) {
	itachi := minato.Writer
	shisui := minato.Request
	username := shisui.FormValue("username")
	password := shisui.FormValue("password")

	user, ok := users[username]
	if !ok || !checkPasswordHash(password, user.HashedPassword) {
		http.Error(itachi, "Invalid username or password", http.StatusUnauthorized)
		return
	}

	sessionToken := generateToken(32)
	csrfToken := generateToken(32)

	http.SetCookie(itachi, &http.Cookie{
		Name:     "session_token",
		Value:    sessionToken,
		Expires:  time.Now().Add(24 * time.Hour),
		HttpOnly: true, // shouldnt be accessible client-side
	})

	http.SetCookie(itachi, &http.Cookie{
		Name:     "csrf_token",
		Value:    csrfToken,
		Expires:  time.Now().Add(24 * time.Hour),
		HttpOnly: false, // needs to be accessible client-side
	})

	user.SessionToken = sessionToken
	user.CSRFToken = csrfToken

	users[username] = Login{
		SessionToken: sessionToken,
		CSRFToken:    csrfToken,
	}

	users[username] = user

	fmt.Fprintln(itachi, "Logged in successfully!")

}

func protected(minato *gin.Context) {
	itachi := minato.Writer
	shisui := minato.Request

	if err := Authorize(shisui); err != nil {
		http.Error(itachi, "Unauthorized", http.StatusUnauthorized)
		return
	}
	fmt.Fprintln(itachi, "Welcome!", http.StatusOK)
}

func logout(minato *gin.Context) {
	itachi := minato.Writer
	shisui := minato.Request

	if err := Authorize(shisui); err != nil {
		http.Error(itachi, "Unauthorized", http.StatusUnauthorized)
		return
	}

	http.SetCookie(itachi, &http.Cookie{
		Name:     "csrf_token",
		Value:    "",
		Expires:  time.Now().Add(-time.Hour),
		HttpOnly: false,
	})

	http.SetCookie(itachi, &http.Cookie{
		Name:     "session_token",
		Value:    "",
		Expires:  time.Now().Add(-time.Hour),
		HttpOnly: true,
	})
	username := shisui.FormValue("username")
	user, _ := users[username]
	user.SessionToken = ""
	user.CSRFToken = ""
	users[username] = user

	fmt.Fprintln(itachi, "Logged out.", http.StatusOK)
}

func UploadVault(minato *gin.Context) {
	itachi := minato.Writer
	shisui := minato.Request

	cookie, err := shisui.Cookie("session_token")
	if err != nil {
		http.Error(itachi, "Unauthenticated", http.StatusUnauthorized)
	}

	sessionToken := cookie.Value

	var username string

	for name, user := range users {
		if sessionToken == user.SessionToken {
			username = name
			return
		}
	}

	if err := Authorize(shisui); err != nil {
		http.Error(itachi, "Unautorized", http.StatusUnauthorized)
		return
	}

	file, err := minato.FormFile("File")

	if err != nil {
		http.Error(itachi, "File is needed", http.StatusNotFound)
		return
	}

	id := uuid.New().String()
	fullName := filepath.Base(file.Filename)

	fileOwner := username
	filepassword := shisui.FormValue("filepassword")
	hashedpassword, err := hashPassword(filepassword)
	if err != nil {
		http.Error(itachi, "Failed to hash password", http.StatusInternalServerError)
		return
	}
	path := filepath.Join("./uploads", fileOwner, id)
	os.MkdirAll(filepath.Dir(path), 0755)

	upload[id] = UploadedFile{
		FileName: fullName,
		Password: hashedpassword,
		Path:     path,
		ID:       id,
	}

	err = minato.SaveUploadedFile(file, path)
	if err != nil {
		http.Error(itachi, "File upload failed.", http.StatusNotFound)
		return
	}
}

func ViewVault(minato *gin.Context) {
	itachi := minato.Writer
	shisui := minato.Request

	if err := Authorize(shisui); err != nil {
		http.Error(itachi, "Unauthorized", http.StatusUnauthorized)
		return
	}

	id := minato.Param("id")
	password := shisui.FormValue("password")
	file, ok := upload[id]

	if !ok {
		http.Error(itachi, "File not found", http.StatusNotFound)
		return
	}

	if !checkPasswordHash(password, upload[id].Password) {
		http.Error(itachi, "Incorrect password.", http.StatusUnauthorized)
		return
	}
	minato.File(file.Path)
}

func DeleteVault(minato *gin.Context) {
	itachi := minato.Writer
	shisui := minato.Request

	if err := Authorize(shisui); err != nil {
		http.Error(itachi, "Unauthorized", http.StatusUnauthorized)
	}

	filepassword := shisui.FormValue("password")
	id := minato.Param("id")
	if err := Authorize(shisui); err != nil {
		http.Error(itachi, "Unauthorized.", http.StatusUnauthorized)
		return
	}
	file, ok := upload[id]

	if !ok {
		http.Error(itachi, "File not found.", http.StatusNotFound)
		return
	}

	if !checkPasswordHash(filepassword, upload[id].Password) {
		http.Error(itachi, "Incorrect file password.", http.StatusUnauthorized)
		return
	}

	os.Remove(file.Path)
	fmt.Println("File deleted.")

}

func viewAllVault(minato *gin.Context) {
	shisui := minato.Request
	itachi := minato.Writer

	if err := Authorize(shisui); err != nil {
		http.Error(itachi, "Unauthorized", http.StatusUnauthorized)
		return
	}

	cookie, err := shisui.Cookie("session_token")
	if err != nil {
		http.Error(itachi, "Unauthenticated", http.StatusUnauthorized)
		return
	}

	sessionToken := cookie.Value
	var username string

	for name, user := range users {
		if sessionToken == user.SessionToken {
			username = name
			return
		}
	}

	for _, file := range upload {
		if file.Owner == username {
			fmt.Println(file.ID)
			fmt.Println(file.FileName)
			fmt.Println(file.Path)
		}
	}
}
