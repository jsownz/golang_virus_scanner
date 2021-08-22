package main

import (
	"crypto/md5"
	"encoding/hex"
	"fmt"
	"io"
	"io/ioutil"
	"net/http"
	"net/url"
	"os"
	"strings"

	"github.com/fatih/color"
)

// Using VirusShare md5 hash database, thank you for your research: https://virusshare.com
var virusshare_uri = "https://virusshare.com/hashfiles/VirusShare_"
var working_directory string
var hash_directory string
var existing_hashes []string
var infected_hashes []string
var hashed_files map[string]string

func check(e error) {
	if e != nil {
		panic(e)
	}
}

func main() {

	update_hashes()

	// hashed_files = make(map[string]string)

	// directory_to_scan := "/home/jason/Documents"
	// files, err := ioutil.ReadDir(directory_to_scan)
	// if err != nil {
	// 	log.Fatal(err)
	// }

	// for _, f := range files {
	// 	if f.IsDir() {
	// 		//fmt.Println(fmt.Sprintf("%s is a Directory", f.Name()))
	// 	} else {
	// 		path := directory_to_scan + "/" + f.Name()
	// 		hash, err := hash_file_md5(path)
	// 		if err == nil {
	// 			hashed_files[hash] = f.Name()
	// 		}
	// 	}
	// }

	// for key, value := range hashed_files {
	// 	fmt.Println("Key:", key, "Value:", value)
	// }
}

func update_hashes() {
	working_directory, err := os.Getwd()
	if err != nil {
		fmt.Println("Error setting working directory")
		panic(err)
	}

	hash_directory = working_directory + "/existing_hashes"

	// Check if the existing hashes directory exsits, make it if not
	if _, err := os.Stat(hash_directory); os.IsNotExist(err) {
		err := os.Mkdir(hash_directory, 0755)
		check(err)
	} else {
		files, err := ioutil.ReadDir(hash_directory)
		check(err)

		for _, f := range files {
			if !f.IsDir() {
				existing_hashes = append(existing_hashes, f.Name())
			}
		}

		if len(existing_hashes) < 1 {
			color.Green("* Downloading first hash file...")
			this_url := virusshare_uri + "00000.md5"

			// Build fileName from fullPath
			fileURL, err := url.Parse(this_url)
			check(err)
			path := fileURL.Path
			segments := strings.Split(path, "/")
			fileName := segments[len(segments)-1]

			// Create blank file
			file, err2 := os.Create(hash_directory + "/" + fileName)
			check(err2)

			client := http.Client{
				CheckRedirect: func(r *http.Request, via []*http.Request) error {
					r.URL.Opaque = r.URL.Path
					return nil
				},
			}
			resp, err3 := client.Get(this_url)
			check(err3)
			if resp.StatusCode == 200 {
				defer resp.Body.Close()
				io.Copy(file, resp.Body)
				defer file.Close()
			}
		}
	}

}

func hash_file_md5(filePath string) (string, error) {
	var returnMD5String string
	file, err := os.Open(filePath)
	if err != nil {
		return returnMD5String, err
	}
	defer file.Close()
	hash := md5.New()
	if _, err := io.Copy(hash, file); err != nil {
		return returnMD5String, err
	}
	hashInBytes := hash.Sum(nil)[:16]
	returnMD5String = hex.EncodeToString(hashInBytes)
	return returnMD5String, nil

}
