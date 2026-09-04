package main

import (
	"context"
	"fmt"
	"net/http"
	"os"
	"path/filepath"
	"time"

	"github.com/google/uuid"

	"github.com/gin-gonic/gin"
	"go.mongodb.org/mongo-driver/bson"
	"go.mongodb.org/mongo-driver/mongo"
	"go.mongodb.org/mongo-driver/mongo/options"
)

type User struct {
	Username       string `bson:"username"`
	HashedPassword string `bson:"hashedpassword"`
	SessionToken   string `bson:"sessiontoken"`
	CSRFToken      string `bson:"csrftoken"`
}

type UploadedFile struct {
	FileName string `bson:"filename"`
	Path     string `bson:"path"`
	Password string `bson:"password"`
	Owner    string `bson:"owner"`
	ID       string `bson:"id"`
}

var client, err = mongo.Connect(
	context.Background(),
	options.Client().ApplyURI("mongodb://iwantmyiphonesscreentowork"),
)

var db = client.Database("vaulty-golang")

var loginInfo = db.Collection("login")
var upload = db.Collection("upload")

func main() {

	if err != nil {
		fmt.Println("Failled to connect to database. Aborting.")
		return
	}

	router := gin.Default()

	router.POST("/register", register)
	router.POST("/login", login)
	router.POST("/logout", logout)
	router.POST("/vault/create", UploadVault)
	router.GET("/vault/:id", ViewVault)
	//router.GET("/vault/all", viewAllVault)
	router.DELETE("/vault/delete", DeleteVault)
	router.Run(":3000")
}

func register(minato *gin.Context) {

	itachi := minato.Writer
	shisui := minato.Request
	username := shisui.FormValue("username")
	password := shisui.FormValue("password")
	hashedpassword, _ := hashPassword(password)

	userInfo := User{
		Username:       username,
		HashedPassword: hashedpassword,
	}
	filter := bson.M{"username": username}

	if len(password) < 8 {

		http.Error(itachi, "Invalid password.", http.StatusNotAcceptable)
		return
	}

	err := loginInfo.FindOne(
		context.Background(),
		filter,
	).Decode(&userInfo)

	if err == nil {
		http.Error(itachi, "User already exists", http.StatusConflict)
		return
	}

	_, err = loginInfo.InsertOne(
		context.Background(),
		userInfo,
	)

	if err != nil {
		return
	}
}

func login(minato *gin.Context) {
	itachi := minato.Writer
	shisui := minato.Request
	username := shisui.FormValue("username")
	password := shisui.FormValue("password")
	hashedpassword, err := hashPassword(password)
	if err != nil {
		fmt.Println("Error hashing password.")
		http.Error(itachi, "Error hashing your password", http.StatusFailedDependency)
		return
	}

	userlogin := User{
		Username:       username,
		HashedPassword: hashedpassword,
	}

	filter := bson.M{"username": username}

	err = loginInfo.FindOne(
		context.Background(),
		filter,
	).Decode(&userlogin)

	if err == mongo.ErrNoDocuments {
		http.Error(itachi, "User not found.", http.StatusNotFound)
		return
	}

	if !checkPasswordHash(password, userlogin.HashedPassword) {
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

	userlogin.CSRFToken = csrfToken
	userlogin.SessionToken = sessionToken

	update := bson.M{
		"$set": bson.M{"sessiontoken": sessionToken, "csrftoken": csrfToken},
	}

	_, err = loginInfo.UpdateOne(
		context.Background(),
		filter,
		update,
	)
	if err != nil {
		return
	}

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
	var user User
	error := loginInfo.FindOne(
		context.Background(),
		bson.M{"username": username},
	).Decode(&user)

	if error == mongo.ErrNoDocuments {
		http.Error(itachi, "Not found.", http.StatusNotFound)
		return
	}

	fmt.Fprintln(itachi, "Logged out.", http.StatusOK)
}

func UploadVault(minato *gin.Context) {
	itachi := minato.Writer
	shisui := minato.Request

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

	filepassword := shisui.FormValue("filepassword")
	hashedpassword, err := hashPassword(filepassword)
	if err != nil {
		http.Error(itachi, "Failed to hash password", http.StatusInternalServerError)
		return
	}
	path := filepath.Join("./uploads", id, fullName)
	os.MkdirAll(filepath.Dir(path), 0755)

	_, err = upload.InsertOne(
		context.Background(),
		bson.M{"id": id, "hashedpassword": hashedpassword, "path": path, "filename": fullName},
	)

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
	var file UploadedFile

	err = upload.FindOne(
		context.Background(),
		bson.M{"id": id},
	).Decode(&file)

	if err == mongo.ErrNoDocuments {
		http.Error(itachi, "File not found", http.StatusNotFound)
		return
	}

	if !checkPasswordHash(password, file.Password) {
		http.Error(itachi, "Incorrect password.", http.StatusUnauthorized)
		return
	}
	minato.File(file.Path)
}

func DeleteVault(minato *gin.Context) {
	itachi := minato.Writer
	shisui := minato.Request

	if err = Authorize(shisui); err != nil {
		http.Error(itachi, "Unauthorized", http.StatusUnauthorized)
		return
	}

	filepassword := shisui.FormValue("password")
	id := minato.Param("id")
	if err := Authorize(shisui); err != nil {
		http.Error(itachi, "Unauthorized.", http.StatusUnauthorized)
		return
	}

	var file UploadedFile

	err = upload.FindOne(
		context.Background(),
		bson.M{"id": id},
	).Decode(&file)

	if err == mongo.ErrNoDocuments {
		http.Error(itachi, "File not found.", http.StatusNotFound)
		return
	}

	if !checkPasswordHash(filepassword, file.Password) {
		http.Error(itachi, "Incorrect file password.", http.StatusUnauthorized)
		return
	}

	os.Remove(file.Path)
	_, err = upload.DeleteOne(
		context.Background(),
		bson.M{"id": id},
	)

	if err != nil {
		http.Error(itachi, "Failed to delete file.", http.StatusFailedDependency)
	}
	fmt.Println("Deleted successfully.")

}

/*func viewAllVault(minato *gin.Context) {
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
	var user User

 err = loginInfo.FindOne(
context.Background(),
bson.M{"sessiontoken": sessionToken},
 ).Decode(&user)

 if err == mongo.ErrNoDocuments {
http.Error(itachi, "User not found.", http.StatusNotFound)
return
 }





	for _, file := range upload {
		if file.Owner == username {
			fmt.Println(file.ID)
			fmt.Println(file.FileName)
			fmt.Println(file.Path)
		}
	}
}
*/
