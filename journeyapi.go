package main

import (
	_ "go.mongodb.org/mongo-driver/bson"
	_ "go.mongodb.org/mongo-driver/mongo"
	_ "go.mongodb.org/mongo-driver/mongo/options"
	_ "go.mongodb.org/mongo-driver/mongo/readpref"
	"io"
	"log"
	"net/http"
)

func getResponse(w http.ResponseWriter, _ *http.Request) {
	io.WriteString(w, "Get Response test")
}

func postResponse(w http.ResponseWriter, _ *http.Request) {

}

func main() {
	http.HandleFunc("/user", getResponse)

	log.Fatal(http.ListenAndServe(":8080", nil))
}
