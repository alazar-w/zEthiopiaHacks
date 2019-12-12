package main

import (
	"html/template"
	"net/http"

	uuid "github.com/satori/go.uuid"
	"golang.org/x/crypto/bcrypt"
)

//User ... this is exported
type User struct {
	Email    string
	UserName string
	Password []byte
}

var tpl *template.Template
var dbUsers = map[string]User{}      //user ID(user name),user
var dbSessions = map[string]string{} //session ID,user ID

func init() {
	tpl = template.Must(template.ParseGlob("templates/*.html"))

	//golang.org/x/crypto/bcrypt, is the encruption method i used to encrypt the password
	bs, _ := bcrypt.GenerateFromPassword([]byte("password"), bcrypt.MinCost)

	//moke user data for login
	dbUsers["james"] = User{Email: "james@gmail.com",
		UserName: "james",
		Password: bs}
}

func main() {
	http.HandleFunc("/", index)
	http.HandleFunc("/login", login)
	http.HandleFunc("/signup", signUp)
	http.HandleFunc("/logout", logout)
	http.Handle("/assets/", http.StripPrefix("/assets", http.FileServer(http.Dir("./templates/assets"))))
	http.Handle("/favicon.ico", http.NotFoundHandler())
	http.ListenAndServe(":8080", nil)
}

func index(w http.ResponseWriter, r *http.Request) {
	u := helper.getUser(w, r)

	tpl.ExecuteTemplate(w, "index.html", u)

}
func login(w http.ResponseWriter, req *http.Request) {
	if helper.alreadyLoggedIn(req) {
		http.Redirect(w, req, "/", http.StatusSeeOther)
		return
	}

	if req.Method == http.MethodPost {
		userName := req.FormValue("username")
		password := req.FormValue("password")

		user, ok := dbUsers[userName]
		if !ok {
			http.Error(w, "username and/or password do not match", http.StatusForbidden)
			return
		}

		err := bcrypt.CompareHashAndPassword(user.Password, []byte(password))
		if err != nil {
			http.Error(w, "username and/or password do not match", http.StatusForbidden)
			return
		}
		sID, _ := uuid.NewV4()
		c := http.Cookie{
			Name:  "session",
			Value: sID.String(),
		}
		http.SetCookie(w, &c)
		dbSessions[c.Value] = userName
		http.Redirect(w, req, "/", http.StatusSeeOther)
		return

	}

	tpl.ExecuteTemplate(w, "login.html", nil)
}
func signUp(w http.ResponseWriter, req *http.Request) {
	if helper.alreadyLoggedIn(req) {

		http.Redirect(w, req, "/", http.StatusSeeOther)
	}

	if req.Method == http.MethodPost {
		email := req.FormValue("email")
		userName := req.FormValue("username")
		password := req.FormValue("password")
		// confPassword := req.FormValue("confirmPassword")

		if _, ok := dbUsers[userName]; ok {
			http.Error(w, "user name already taken", http.StatusForbidden)
			return
		}
		sID, _ := uuid.NewV4()
		c := http.Cookie{
			Name:  "session",
			Value: sID.String(),
		}
		http.SetCookie(w, &c)

		dbSessions[c.Value] = userName

		pass, _ := bcrypt.GenerateFromPassword([]byte(password), bcrypt.MinCost)
		u := User{
			email, userName, pass,
		}
		dbUsers[userName] = u
		http.Redirect(w, req, "/", http.StatusSeeOther)
	}
	tpl.ExecuteTemplate(w, "signup.html", nil)
}
func logout(w http.ResponseWriter, req *http.Request) {
	if !helper.alreadyLoggedIn(req) {
		http.Redirect(w, req, "/", http.StatusSeeOther)
		return
	}
	c, _ := req.Cookie("session")
	//delete the session
	delete(dbSessions, c.Value)

	//remove the cookie

	c = &http.Cookie{
		Name:   "session",
		Value:  "",
		MaxAge: -1,
	}
	http.SetCookie(w, c)
	http.Redirect(w, req, "/login", http.StatusSeeOther)

}
