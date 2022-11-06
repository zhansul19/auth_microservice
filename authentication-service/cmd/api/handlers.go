package main

import (
	"errors"
	"fmt"
	"log"
	"net/http"

	"github.com/zhansul19/test_service/authentication/data"
)


func (app *Config) Authenticate(w http.ResponseWriter, r *http.Request) {
	var requestPayload struct {
		Email 	 string `json:"email"`
		Password string `json:"password"`
	}

	err := app.readJSON(w, r, &requestPayload)
	if err != nil {
		app.errorJSON(w, err, http.StatusBadRequest)
		return
	}

	// validate the user against the database
	user, err := app.Models.User.GetByEmail(requestPayload.Email)
	if err != nil {
		app.errorJSON(w, errors.New("invalid credentials"), http.StatusBadRequest)
		return
	}

	valid, err := user.PasswordMatches(requestPayload.Password)
	if err != nil || !valid {
		app.errorJSON(w, errors.New("invalid credentials"), http.StatusBadRequest)
		return
	}

	payload := jsonResponse {
		Error: false,
		Message: fmt.Sprintf("Logged in user %s", user.Email),
		Data: user,
	}

	app.writeJSON(w, http.StatusAccepted, payload)
}
func (app *Config) Register(w http.ResponseWriter, r *http.Request) {
	var requestPayload struct {
		Email string `json:"email"`
		Password string `json:"password"`
		PasswordValidation string `json:"password_validation"`
	}

	err := app.readJSON(w, r, &requestPayload)
	if err != nil {
		app.errorJSON(w, err, http.StatusBadRequest)
		return
	}

	log.Println(requestPayload)

	// validate the user does not exist against the database
	user, _ := app.Models.User.GetByEmail(requestPayload.Email)
	if user!= nil {
		app.errorJSON(w, errors.New("user alredy exists"), http.StatusBadRequest)
		return
	}

	if requestPayload.Password!=requestPayload.PasswordValidation {
		app.errorJSON(w, errors.New("passwords are not matching"), http.StatusBadRequest)
		return
	}
	newUser:=data.User{
		Email: requestPayload.Email,
		FirstName: data.RandomString(6),
		LastName: data.RandomString(6),
		Password: requestPayload.Password,
	}
	_,err=app.Models.User.Insert(newUser)
	if err != nil {
		app.errorJSON(w, errors.New("could  not create"), http.StatusBadRequest)
		return	
	}

	payload := jsonResponse {
		Error: false,
		Message: fmt.Sprintf("Created user %s", newUser.Email),
		Data: newUser,
	}

	app.writeJSON(w, http.StatusAccepted, payload)
}