package main

import (
	"io"
	"log"
	"net/http"

	"go.mongodb.org/mongo-driver/bson"
	"go.mongodb.org/mongo-driver/mongo"
	"go.mongodb.org/mongo-driver/mongo/options"
	"go.mongodb.org/mongo-driver/mongo/readpref"
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
