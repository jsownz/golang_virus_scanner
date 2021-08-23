package main

import (
	"crypto/md5"
	"encoding/hex"
	"fmt"
	"io"
	"io/fs"
	"io/ioutil"
	"net/http"
	"net/url"
	"os"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/akamensky/argparse"
	"github.com/fatih/color"
)

// Using VirusShare md5 hash database, thank you for your research: https://virusshare.com
var virusshare_uri string = "https://virusshare.com/hashfiles/VirusShare_"
var working_directory string
var hash_directory string
var scanned_count int = 0
var existing_hashes []string
var infected_hashes []string
var hashed_files map[string]string
var virus_defs []string

func check(e error) {
	if e != nil {
		panic(e)
	}
}

func main() {

	parser := argparse.NewParser("go_virus_scanner", "Scans viruses duh")
	// Create string flag
	scan_directory_string := parser.String("d", "dirpath", &argparse.Options{Required: true, Help: "Directory to scan"})
	// Parse input
	err := parser.Parse(os.Args)
	if err != nil {
		fmt.Print(parser.Usage(err))
		os.Exit(3)
	}

	update_hashes()
	load_virus_defs()

	start := time.Now()

	directory_to_scan := *scan_directory_string
	scan_directory(directory_to_scan)

	duration := time.Since(start)
	fmt.Println("")
	fmt.Println(fmt.Sprintf("Completed in %dms.", (duration / 1000000)))

	if len(infected_hashes) > 0 {
		color.Red("%d Infections", len(infected_hashes))
		for _, infection := range infected_hashes {
			color.Red("%s: %s", hashed_files[infection], infection)
		}
	} else {
		color.Green("No infections!")
	}
}

func load_virus_defs() {
	color.Cyan("Loading Virus Hashes...")
	for _, hash_file := range existing_hashes {
		b, err := ioutil.ReadFile(hash_directory + "/" + hash_file)
		check(err)
		s := string(b)
		virus_defs = append(virus_defs, s)
	}
	color.Green("Virus hashes loaded.")
}

func scan_directory(directory_name string) {
	fmt.Println(fmt.Sprintf("Scanning Directory: %s...", directory_name))
	hashed_files = make(map[string]string)

	files_to_hash, err := ioutil.ReadDir(directory_name)
	check(err)

	for _, f := range files_to_hash {
		filename := directory_name + "/" + f.Name()
		recurse_and_hash(filename, f)
	}

	fmt.Println(fmt.Sprintf("Scanning %d files...", len(hashed_files)))
	compare_hashes()
}

func compare_hashes() {
	counter := 1
	var wg sync.WaitGroup
	maxGoroutines := 100
	guard := make(chan struct{}, maxGoroutines)

	for key, _ := range hashed_files {
		wg.Add(1)
		// go compare_hash(key, counter, &wg)
		guard <- struct{}{}
		go func(key string, counter int, wg *sync.WaitGroup) {
			compare_hash(key, counter, wg)
			counter++
			<-guard
		}(key, counter, &wg)
	}
	wg.Wait()
}

func compare_hash(hash string, counter int, wg *sync.WaitGroup) {
	defer wg.Done()
	// func compare_hash(hash string, counter int) {
	for _, hash_file := range virus_defs {
		if strings.Contains(hash_file, hash) {
			fmt.Println("")
			color.Red("Infected File: %s", hashed_files[hash])
			infected_hashes = append(infected_hashes, hash)
			break
		}
	}

	scanned_count++
	output_progress()
}

func output_progress() {
	fmt.Printf("\r%d/%d Scanned.", scanned_count, len(hashed_files))
}

func recurse_and_hash(filename string, f fs.FileInfo) {
	if !f.IsDir() {
		hash, err := hash_file_md5(filename)
		if err == nil {
			hashed_files[hash] = filename
		}
	} else {
		child_files, err2 := ioutil.ReadDir(filename)
		check(err2)

		for _, child_file := range child_files {
			child_filename := filename + "/" + child_file.Name()
			recurse_and_hash(child_filename, child_file)
		}
	}
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

		sort.Strings(existing_hashes)

		if len(existing_hashes) < 1 {
			color.Green("* Downloading first hash file...")
			this_url := virusshare_uri + "00000.md5"

			download_hash_file(this_url)
		} else {

			last_hashfile := existing_hashes[len(existing_hashes)-1]
			lh_segments := strings.Split(last_hashfile, "_")[1]
			last_hash_file_number, hash_err := strconv.Atoi(strings.Split(lh_segments, ".")[0])
			check(hash_err)
			next_hash_file_number := last_hash_file_number + 1

			color.Cyan("Checking for new hashes...")
			recent_hash := fmt.Sprintf("%05d", last_hash_file_number)
			redownload_url := virusshare_uri + recent_hash + ".md5"

			download_hash_file(redownload_url)

			for i := next_hash_file_number; i < 10000; i++ {
				next_hash := fmt.Sprintf("%05d", i)
				next_url := virusshare_uri + next_hash + ".md5"
				// Build fileName from fullPath
				fileURL, err := url.Parse(next_url)
				check(err)
				path := fileURL.Path
				segments := strings.Split(path, "/")
				fileName := segments[len(segments)-1]

				client := http.Client{
					CheckRedirect: func(r *http.Request, via []*http.Request) error {
						r.URL.Opaque = r.URL.Path
						return nil
					},
				}
				resp, err3 := client.Get(next_url)
				check(err3)
				if resp.StatusCode == 200 {
					// Create blank file
					file, err2 := os.Create(hash_directory + "/" + fileName)
					check(err2)

					defer resp.Body.Close()
					io.Copy(file, resp.Body)
					defer file.Close()
					fmt.Println(fmt.Sprintf("Downloaded %s", fileName))
				} else {
					color.Green("Hashes up-to-date.")
					break
				}
			}
		}

	}

}

func download_hash_file(this_url string) {
	// Build fileName from fullPath
	fileURL, err := url.Parse(this_url)
	check(err)
	path := fileURL.Path
	segments := strings.Split(path, "/")
	fileName := segments[len(segments)-1]

	client := http.Client{
		CheckRedirect: func(r *http.Request, via []*http.Request) error {
			r.URL.Opaque = r.URL.Path
			return nil
		},
	}
	resp, err3 := client.Get(this_url)
	check(err3)
	if resp.StatusCode == 200 {
		// Create blank file
		file, err2 := os.Create(hash_directory + "/" + fileName)
		check(err2)

		defer resp.Body.Close()
		io.Copy(file, resp.Body)
		defer file.Close()
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
