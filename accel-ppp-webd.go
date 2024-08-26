/*
	golang backend for ACCEL-PPP WEB
	SPDX-License-Identifier: LGPL-2.1-or-later
	(c) 2024 Denys Fedoryshchenko <denys.f@collabora.com>
*/

package main

import (
	"bufio"
	"encoding/json"
	"log"
	"log/syslog"
	"net/http"
	"os"
	"os/exec"
	"regexp"
	"strconv"
	"strings"
	"time"

	// jwt https://github.com/golang-jwt/jwt
	"flag"

	jwt "github.com/golang-jwt/jwt"
)

var jwtSecret string
var bindaddr string
var noauth bool

func getFileContent(filename string) string {
	// verify if file exists
	_, err := os.Stat(filename)
	if os.IsNotExist(err) {
		log.Println("File not found: " + filename)
		return ""
	}
	file, err := os.Open(filename)
	if err != nil {
		log.Fatal(err)
	}
	defer file.Close()

	// read all lines
	//scanner := bufio.NewScanner(file)
	//scanner.Scan()
	//return scanner.Text()
	content := ""
	scanner := bufio.NewScanner(file)
	for scanner.Scan() {
		content += scanner.Text()
		content += "\n"
	}
	return content
}

func verifyToken(jwtdata string) bool {
	// parse token
	token, err := jwt.Parse(jwtdata, func(token *jwt.Token) (interface{}, error) {
		return []byte(jwtSecret), nil
	})
	if err != nil {
		return false
	}
	// check if token is valid
	if token.Valid {
		return true
	}
	return false
}

func verifyAuth(w http.ResponseWriter, r *http.Request) bool {
	if noauth {
		return true
	}
	// check cookie
	cookie, err := r.Cookie("jwt")
	if err != nil {
		//http.Error(w, "No cookie", http.StatusUnauthorized)
		// redirect to login.html
		http.Redirect(w, r, "/login.html", http.StatusSeeOther)
		return false
	}
	// check token
	if !verifyToken(cookie.Value) {
		//http.Error(w, "Invalid token", http.StatusUnauthorized)
		// redirect to login.html
		http.Redirect(w, r, "/login.html", http.StatusSeeOther)
		return false
	}
	return true
}

func execCommand(command string) string {
	// execute command and collect output
	cmd := exec.Command("sh", "-c", command)
	out, err := cmd.Output()
	if err != nil {
		log.Fatal(err)
	}

	return string(out)
}

type Session struct {
	Ifname string `json:"ifname"`
	User   string `json:"user"`
	Mac    string `json:"mac"`
	Ip     string `json:"ip"`
	Proto  string `json:"proto"`
	Comp   string `json:"comp"`
	State  string `json:"state"`
	Uptime string `json:"uptime"`
}

type Sysinfo struct {
	Accelstats   string    `json:"accelstats"`
	Accelversion string    `json:"accelversion"`
	Systemload   float32   `json:"systemload"`
	Sessions     []Session `json:"sessions"`
}

func convertStringToFloat(s string) float32 {
	f, err := strconv.ParseFloat(s, 32)
	if err != nil {
		log.Fatal(err)
	}
	return float32(f)
}

func getSessions() []Session {
	// get sessions
	accelStats := execCommand("accel-cmd show sessions")
	lines := strings.Split(accelStats, "\n")
	sessions := make([]Session, 0)
	count := 0
	for _, line := range lines {
		// split by | and remove spaces, field might be empty!
		// like comp in typical pppoe setup is empty
		fields := strings.FieldsFunc(line, func(r rune) bool {
			return r == '|'
		})
		if len(fields) < 8 {
			continue
		}
		// skip first line
		if count == 0 {
			count++
			continue
		}
		// iterate over fields and strip spaces
		for i, field := range fields {
			fields[i] = strings.TrimSpace(field)
		}
		session := Session{fields[0], fields[1], fields[2], fields[3], fields[4], fields[5], fields[6], fields[7]}
		sessions = append(sessions, session)
	}
	return sessions
}

func getCoreCount() int {
	// get number of cores
	snapshot1 := getFileContent("/proc/cpuinfo")
	fields1 := strings.Fields(snapshot1)
	cores := 0
	for _, field := range fields1 {
		if field == "processor" {
			cores++
		}
	}
	return cores
}

type Load struct {
	Total uint64
	Idle  uint64
}

type LoadSnapshot struct {
	TotalLoad Load
	CoreLoad  []Load
}

func loadProcessLine(line string) (string, []uint64) {
	// split by space
	fields := strings.Fields(line)
	// get process name
	process := fields[0]
	// get process load
	loads := make([]uint64, 0)
	for i := 1; i < len(fields); i++ {
		load, err := strconv.ParseUint(fields[i], 10, 64)
		if err != nil {
			log.Fatal(err)
		}
		loads = append(loads, load)
	}
	return process, loads
}

func getCoreLoad(loads []uint64) Load {
	var load Load
	// 3rd field is idle
	numfields := len(loads)
	for i := 0; i < numfields; i++ {
		if i == 3 {
			load.Idle = loads[i]
		} else {
			load.Total += loads[i]
		}
	}
	return load
}

func CoreLoadSnapshot() LoadSnapshot {
	var totalload LoadSnapshot
	// get number of cores
	fh, err := os.Open("/proc/stat")
	if err != nil {
		log.Fatal(err)
	}
	scanner := bufio.NewScanner(fh)
	linen := 0
	for scanner.Scan() {
		line := scanner.Text()
		linen++
		// total
		if linen == 1 {
			// total
			_, loads := loadProcessLine(line)
			for i := 0; i < len(loads); i++ {
				if i == 3 {
					totalload.TotalLoad.Idle = loads[i]
				} else {
					totalload.TotalLoad.Total += loads[i]
				}
			}
		} else {
			// core
			procname, loads := loadProcessLine(line)
			// check if it's core (starts with cpu)
			if strings.HasPrefix(procname, "cpu") {
				coreload := getCoreLoad(loads)
				totalload.CoreLoad = append(totalload.CoreLoad, coreload)
			}
		}
	}
	return totalload
}

func getSystemload() float32 {
	var diffLoad LoadSnapshot
	// snapshots with delay of 1 sec
	snapshot1 := CoreLoadSnapshot()
	time.Sleep(1 * time.Second)
	snapshot2 := CoreLoadSnapshot()

	// calculate diff
	diffLoad.TotalLoad.Total = snapshot2.TotalLoad.Total - snapshot1.TotalLoad.Total
	diffLoad.TotalLoad.Idle = snapshot2.TotalLoad.Idle - snapshot1.TotalLoad.Idle
	numcores := len(snapshot1.CoreLoad)
	if numcores != len(snapshot2.CoreLoad) {
		log.Fatal("Number of cores mismatch")
	}
	if numcores == 0 {
		log.Fatal("No cores found?")
	}
	for i := 0; i < numcores; i++ {
		diffLoad.CoreLoad = append(diffLoad.CoreLoad, Load{})
		diffLoad.CoreLoad[i].Total = snapshot2.CoreLoad[i].Total - snapshot1.CoreLoad[i].Total
	}
	sumTotal := diffLoad.TotalLoad.Total + diffLoad.TotalLoad.Idle
	totalCPUbusy := diffLoad.TotalLoad.Total * 100 / sumTotal
	return convertStringToFloat(strconv.FormatUint(totalCPUbusy, 10))
}

func handlerSysinfo(w http.ResponseWriter, r *http.Request) {
	accelStats := execCommand("accel-cmd show stat")
	// accel-cmd -V
	accelVersion := execCommand("accel-cmd -V")
	// get CPU load
	systemLoad := getSystemload()
	// pack in accelstats json
	sessions := getSessions()
	sysinfo := Sysinfo{accelStats, accelVersion, systemLoad, sessions}
	// output json
	json.NewEncoder(w).Encode(sysinfo)
}

func handleTerm(w http.ResponseWriter, r *http.Request) {
	ifname := r.URL.Query().Get("ifname")
	if ifname == "" {
		http.Error(w, "No ifname specified", http.StatusBadRequest)
		return
	}
	re := regexp.MustCompile("^[a-z0-9]+$")
	if !re.MatchString(ifname) {
		http.Error(w, "Invalid ifname", http.StatusBadRequest)
		return
	}

	execCommand("accel-cmd terminate if " + ifname)
	// return json result=ok
	output := make(map[string]string)
	output["result"] = "ok"
	json.NewEncoder(w).Encode(output)
}

func handleLive(w http.ResponseWriter, r *http.Request) {
	// return live.html
	http.ServeFile(w, r, "live.html")
}

func handleStat(w http.ResponseWriter, r *http.Request) {
	ifname := r.URL.Query().Get("ifname")
	if ifname == "" {
		http.Error(w, "No ifname specified", http.StatusBadRequest)
		return
	}
	// sanitize ifname ^[a-z0-9]+$
	re := regexp.MustCompile("^[a-z0-9]+$")
	if !re.MatchString(ifname) {
		http.Error(w, "Invalid ifname", http.StatusBadRequest)
		return
	}
	// /sys/class/net/ppp100/statistics/rx_bytes and tx_bytes
	rxBytes := getFileContent("/sys/class/net/" + ifname + "/statistics/rx_bytes")
	txBytes := getFileContent("/sys/class/net/" + ifname + "/statistics/tx_bytes")
	unixTime := time.Now().Unix()
	// pack in json
	output := make(map[string]string)
	output["rx_bytes"] = rxBytes
	output["tx_bytes"] = txBytes
	output["timestamp"] = strconv.FormatInt(unixTime, 10)
	// output json
	json.NewEncoder(w).Encode(output)
}

func handleLogin(w http.ResponseWriter, r *http.Request) {
	// is POST?
	if r.Method != "POST" {
		http.Error(w, "Invalid method", http.StatusBadRequest)
		return
	}
	// is Content-Type: application/json?
	if r.Header["Content-Type"] == nil {
		http.Error(w, "No Content-Type header", http.StatusBadRequest)
		return
	}
	if r.Header["Content-Type"][0] != "application/json" {
		http.Error(w, "Invalid Content-Type", http.StatusBadRequest)
		return
	}
	// parse json
	var data map[string]string
	err := json.NewDecoder(r.Body).Decode(&data)

	if err != nil {
		http.Error(w, "Invalid JSON", http.StatusBadRequest)
		return
	}
	// is token present?
	if data["token"] == "" {
		http.Error(w, "No token", http.StatusBadRequest)
		return
	}
	// check token
	if !verifyToken(data["token"]) {
		http.Error(w, "Invalid token", http.StatusUnauthorized)
		return
	}
	// set token in cookie
	http.SetCookie(w, &http.Cookie{
		Name:     "jwt",
		Value:    data["token"],
		HttpOnly: true,
		Path:     "/",
	})
	// return json result=ok
	output := make(map[string]string)
	output["result"] = "ok"
	json.NewEncoder(w).Encode(output)
}

type IfactionResult struct {
	Result  string `json:"result"`
	Content string `json:"content"`
}

func handlerIfaction(w http.ResponseWriter, r *http.Request) {
	var result IfactionResult
	ifname := r.URL.Query().Get("ifname")
	action := r.URL.Query().Get("action")
	if ifname == "" {
		result.Result = "error"
		result.Content = "No ifname specified"
		json.NewEncoder(w).Encode(result)
		http.Error(w, "No ifname specified", http.StatusBadRequest)
		return
	}
	if action == "" {
		result.Result = "error"
		result.Content = "No action specified"
		json.NewEncoder(w).Encode(result)
		http.Error(w, "No action specified", http.StatusBadRequest)
		return
	}
	// sanitize ifname ^[a-z0-9]+$
	re := regexp.MustCompile("^[a-z0-9]+$")
	if !re.MatchString(ifname) {
		result.Result = "error"
		result.Content = "Invalid ifname"
		json.NewEncoder(w).Encode(result)
		http.Error(w, "Invalid ifname", http.StatusBadRequest)
		return
	}
	// action - showshaper
	if action == "shaperinfo" {
		content := ""
		output := execCommand("tc qdisc show dev " + ifname)
		content += "Qdisc:\n" + output + "\n"
		output = execCommand("tc class show dev " + ifname)
		content += "Class:\n" + output + "\n"
		output = execCommand("tc filter show dev " + ifname)
		content += "Filter:\n" + output + "\n"
		result.Result = "ok"
		result.Content = content
		json.NewEncoder(w).Encode(result)
		return
	}
	// action - showrad (/var/run/radattr.<ifname>)
	if action == "showrad" {
		content := getFileContent("/var/run/radattr." + ifname)
		result.Result = "ok"
		result.Content = content
		json.NewEncoder(w).Encode(result)
		return
	}
}

func verifyStart() string {
	// is accel-cmd available?
	_, err := exec.LookPath("accel-cmd")
	if err != nil {
		return "accel-cmd not found"
	}
	// is accel-cmd return valid output?
	out := execCommand("accel-cmd show stat")
	if out == "" {
		return "accel-cmd show stat returned empty output"
	}
	return ""
}

func genJWTToken(username string) {
	// generate JWT token for user
	token := jwt.New(jwt.SigningMethodHS256)
	claims := token.Claims.(jwt.MapClaims)
	claims["username"] = username
	claims["exp"] = time.Now().Add(time.Hour * 24 * 365).Unix()
	tokenString, err := token.SignedString([]byte(jwtSecret))
	if err != nil {
		log.Fatal(err)
	}
	log.Println(tokenString)
}

func setLogSyslog() {
	// set log to syslog
	logwriter, err := syslog.New(syslog.LOG_NOTICE, "accel-ppp-webd")
	if err != nil {
		log.Fatal(err)
	}
	log.SetOutput(logwriter)
}

func setLogFilename(filename string) {
	// set log to file
	file, err := os.OpenFile(filename, os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0666)
	if err != nil {
		log.Fatal(err)
	}
	log.SetOutput(file)
}

func main() {
	var genuser string
	var stderr bool
	var logfilename string
	// arguments:
	// -jwtsecret <secret>
	flag.StringVar(&jwtSecret, "jwtsecret", "", "JWT secret")
	// -bindaddr <ip:port>
	flag.StringVar(&bindaddr, "bindaddr", ":8080", "Bind address")
	// -noauth
	flag.BoolVar(&noauth, "noauth", false, "Disable authentication")
	// -genuser <username>
	flag.StringVar(&genuser, "genuser", "", "Generate JWT token for username")
	// -stderr
	flag.BoolVar(&stderr, "stderr", false, "Log to stderr or file, otherwise to syslog(default)")
	// -logfilename <filename>
	flag.StringVar(&logfilename, "logfile", "", "Log filename")

	flag.Parse()

	if logfilename != "" {
		setLogFilename(logfilename)
	} else if stderr {
		log.SetOutput(os.Stderr)
	} else {
		setLogSyslog()
	}

	// generate JWT token for user
	if genuser != "" {
		genJWTToken(genuser)
		return
	}

	// check if start requirements are met
	err := verifyStart()
	if err != "" {
		log.Fatal(err)
	}

	// login.html
	http.HandleFunc("/login.html", func(w http.ResponseWriter, r *http.Request) {
		http.ServeFile(w, r, "login.html")
	})

	// /api/ifaction?ifname=<ifname>&action=<command>
	http.HandleFunc("/api/ifaction", func(w http.ResponseWriter, r *http.Request) {
		if !verifyAuth(w, r) {
			return
		}
		handlerIfaction(w, r)
	})

	http.HandleFunc("/api/sysinfo", func(w http.ResponseWriter, r *http.Request) {
		if !verifyAuth(w, r) {
			return
		}
		handlerSysinfo(w, r)
	})

	http.HandleFunc("/api/terminate", func(w http.ResponseWriter, r *http.Request) {
		if !verifyAuth(w, r) {
			return
		}
		handleTerm(w, r)
	})

	http.HandleFunc("/live", func(w http.ResponseWriter, r *http.Request) {
		if !verifyAuth(w, r) {
			return
		}

		handleLive(w, r)
	})

	http.HandleFunc("/api/stat", func(w http.ResponseWriter, r *http.Request) {
		if !verifyAuth(w, r) {
			return
		}
		handleStat(w, r)
	})

	// /api/login verify token in body as json {token: <token>} and set it in cookie as httponly
	http.HandleFunc("/api/login", func(w http.ResponseWriter, r *http.Request) {
		handleLogin(w, r)
	})

	http.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		if !verifyAuth(w, r) {
			return
		}
		http.ServeFile(w, r, "index.html")
	})

	log.Fatal(http.ListenAndServe(bindaddr, nil))
}
