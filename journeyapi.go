package main

import (
	"bytes"
	"context"
	"crypto/rand"
	"crypto/sha512"
	"encoding/base64"
	"go.mongodb.org/mongo-driver/bson"
	"go.mongodb.org/mongo-driver/bson/primitive"
	"go.mongodb.org/mongo-driver/mongo"
	"go.mongodb.org/mongo-driver/mongo/options"
	"io"
	"log"
	"net/http"
	"net/url"
	"strings"
)

type USERINFO struct {
	Username string `json:"username"`
	Password string `json:"password"`
	Book     string `json:"book"`
}

func getResponse(w http.ResponseWriter, req *http.Request) {
	u, err := url.Parse(req.RequestURI)
	if err != nil {
		log.Fatal(err)
	}
	//now we split the query up with an &
	splitQuery := strings.Split(u.RawQuery, "&")
	var username string
	var password string
	for _, queryStr := range splitQuery {
		if strings.Contains(queryStr, "username=") {
			username = queryStr[len("username="):]
		}
		if strings.Contains(queryStr, "password=") {
			password = queryStr[len("password="):]
		}
	}
	var user primitive.M
	err = db().Database("journeyTest").Collection("users").FindOne(context.TODO(), bson.M{"username": username}).Decode(&user)
	if user == nil { //user does not exist
		io.WriteString(w, "Error, incorrect username or password or user does not exist\n")
		//hash the password anyways so we can prevent time based attacks (e.g the attacker can't find out whether a username exists or not based on how long it takes to determine something)
		hasher := sha512.New()
		hasher.Write([]byte(password))
	} else {
		//let's get the salt
		encodedHashedPwandSalt := strings.Split(user["password"].(string), ":")
		hasher := sha512.New()
		decodedSalt, err := base64.StdEncoding.DecodeString(encodedHashedPwandSalt[1])
		if err != nil {
			log.Fatal(err)
		} else {
			hasher.Write(append([]byte(password), decodedSalt...))
			decodedHashedpw, err := base64.StdEncoding.DecodeString(encodedHashedPwandSalt[0])
			if err != nil {
				log.Fatal(err)
			} else {
				if bytes.Compare(decodedHashedpw, hasher.Sum(nil)) != 0 {
					//password is incorrect
					io.WriteString(w, "Error, incorrect username or password or user does not exist\n")
				} else {
					//password is correct
					io.WriteString(w, user["book"].(string))
					return
				}
			}
		}
	}
	io.WriteString(w, "Unable to retrieve book")

}

func postResponse(w http.ResponseWriter, req *http.Request) {
	if err := req.ParseForm(); err != nil {
		log.Fatal(err)
	} else {
		username, err := url.QueryUnescape(req.FormValue("username"))
		pw := req.FormValue("password")
		book := req.FormValue("book")

		if err != nil {
			log.Fatal(err)
		} else {
			//let's secure the password, first create a salt of 16 bytes
			salt := make([]byte, 16)
			_, err = rand.Read(salt)

			if err != nil {
				log.Fatal("Error creating salt: " + err.Error())
			} else {
				//let's make sure it doesn't already exist
				var preexist primitive.M
				err = db().Database("journeyTest").Collection("users").FindOne(context.TODO(), bson.M{"username": username}).Decode(&preexist)
				if preexist != nil {
					io.WriteString(w, "User already exists\n")
				} else {
					hasher := sha512.New()
					hasher.Write(append([]byte(pw), salt...))
					//now let's put everything in
					toInsert := USERINFO{
						Username: username,
						Password: base64.StdEncoding.EncodeToString(hasher.Sum(nil)) + ":" + base64.StdEncoding.EncodeToString(salt),
						Book:     book,
					}

					_, err := db().Database("journeyTest").Collection("users").InsertOne(context.TODO(), toInsert)
					if err != nil {
						log.Fatal(err)
					} else {
						io.WriteString(w, "Success")
						return
					}
				}
			}
		}
	}
	io.WriteString(w, "Failed to add user")
}

func delResponse(w http.ResponseWriter, req *http.Request) {
	w.Header().Set("Access-Control-Allow-Origin", "*")
	w.Header().Set("Access-Control-Allow-Methods", "POST, GET, OPTIONS, PUT, DELETE")
	w.Header().Set("Access-Control-Allow-Headers", "Accept, Content-Type, Content-Length, Accept-Encoding, X-CSRF-Token, Authorization")
	u, err := url.Parse(req.RequestURI)
	if err != nil {
		log.Fatal(err)
	}
	//now we split the query up with an &
	splitQuery := strings.Split(u.RawQuery, "&")
	var username string
	var password string
	for _, queryStr := range splitQuery {
		if strings.Contains(queryStr, "username=") {
			username = queryStr[len("username="):]
		}
		if strings.Contains(queryStr, "password=") {
			password = queryStr[len("password="):]
		}
	}
	var user primitive.M
	err = db().Database("journeyTest").Collection("users").FindOne(context.TODO(), bson.M{"username": username}).Decode(&user)
	if password != "" {
		//we have a password let's check it
		if user == nil { //user does not exist
			//hash the password anyways so we can prevent time based attacks (e.g the attacker can't find out whether a username exists or not based on how long it takes to determine something)
			hasher := sha512.New()
			hasher.Write([]byte(password))
			io.WriteString(w, "Error, incorrect username or password or user does not exist\n")
			return
		} else {
			//let's get the salt
			encodedHashedPwandSalt := strings.Split(user["password"].(string), ":")
			hasher := sha512.New()
			decodedSalt, err := base64.StdEncoding.DecodeString(encodedHashedPwandSalt[1])
			if err != nil {
				log.Fatal(err)
			} else {
				hasher.Write(append([]byte(password), decodedSalt...))
				decodedHashedpw, err := base64.StdEncoding.DecodeString(encodedHashedPwandSalt[0])
				if err != nil {
					log.Fatal(err)
				} else {
					if bytes.Compare(decodedHashedpw, hasher.Sum(nil)) != 0 {
						//password is incorrect
						io.WriteString(w, "Error, incorrect username or password or user does not exist\n")
						return
					} else {
						//password is correct
						_, err = db().Database("journeyTest").Collection("users").DeleteOne(context.TODO(), bson.M{"username": username})
						if err != nil {
							log.Fatal(err)
						}
						io.WriteString(w, "Successfully deleted")
						return
					}
				}
			}
		}

	} else {
		err = db().Database("journeyTest").Collection("users").FindOne(context.TODO(), bson.M{"username": username}).Decode(&user)
		if user == nil { //user does not exist
			io.WriteString(w, "Error, User does not exist\n")
			return
		} else {
			_, err = db().Database("journeyTest").Collection("users").DeleteOne(context.TODO(), bson.M{"username": username})
			if err != nil {
				log.Fatal(err)
			}
			io.WriteString(w, "Successfully deleted")
			return
		}
	}
}

func pickResponse(w http.ResponseWriter, req *http.Request) {
	if req.Method == "GET" {
		getResponse(w, req)
	} else if req.Method == "POST" {
		postResponse(w, req)
	} else if req.Method == "DELETE" {
		delResponse(w, req)
	} else if req.Method == "OPTIONS" {
		//ignore it
		w.Header().Set("Access-Control-Allow-Origin", "*")
		w.Header().Set("Access-Control-Allow-Methods", "POST, GET, OPTIONS, PUT, DELETE")
		w.Header().Set("Access-Control-Allow-Headers", "Accept, Content-Type, Content-Length, Accept-Encoding, X-CSRF-Token, Authorization")
	} else {
		log.Fatal("Error: undefined request type " + req.Method)
	}

}

func db() *mongo.Client {
	db, err := mongo.NewClient(options.Client().ApplyURI("mongodb://127.0.0.1:27017/"))
	if err != nil {
		log.Fatal(err)
	}

	err = db.Connect(context.TODO())
	if err != nil {
		log.Fatal(err)
	}

	err = db.Ping(context.TODO(), nil)
	if err != nil {
		log.Fatal(err)
	}

	return db
}

func main() {
	http.HandleFunc("/user", pickResponse)

	log.Fatal(http.ListenAndServe(":8080", nil))
}
