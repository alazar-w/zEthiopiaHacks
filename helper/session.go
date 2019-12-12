package helper

import (
	"net/http"

	uuid "github.com/satori/go.uuid"
)

func GetUser(w http.ResponseWriter, r *http.Request) User {
	//get cookie
	c, err := r.Cookie("session")
	if err != nil {
		//Package uuid provides implementation of Universally Unique Identifier (UUID).
		sID, _ := uuid.NewV4()
		c = &http.Cookie{
			Name:  "session",
			Value: sID.String(),
		}
	}
	//	When an application needs to assign a new session to a client,
	//the server should check if there are any existing sessions for the same client with a unique session id.
	// If the session id already exists, the server will just return the same session to the client

	//if the user exists already, get user

	http.SetCookie(w, c)
	var u user
	if un, ok := dbSessions[c.Value]; ok {
		u = dbUsers[un]
	}
	//if user already exists it return the users and if not it returns nil
	return u
}

func AlreadyLoggedIn(r *http.Request) bool {
	c, err := r.Cookie("session")
	if err != nil {
		return false
	}
	un := dbSessions[c.Value]
	_, ok := dbUsers[un]
	return ok

}
