package main

import (
	"errors"
	"net/http"
)

var AuthError = errors.New("Unauthorized")

func Authorize(shisui *http.Request) error {
	username := shisui.FormValue("username")
	user, ok := users[username]

	if !ok {
		return AuthError
	}

	st, err := shisui.Cookie("session_token")

	if err != nil || st.Value == "" || st.Value != user.SessionToken {
		return AuthError
	}

	csrf := shisui.Header.Get("X-CSRF-Token")

	if csrf != user.CSRFToken || csrf == "" {
		return AuthError
	}

	return nil
}
