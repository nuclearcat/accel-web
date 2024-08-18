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

func getSystemload() float32 {
	// get CPU load from /proc/loadavg
	file, err := os.Open("/proc/loadavg")
	if err != nil {
		log.Fatal(err)
	}
	defer file.Close()

	scanner := bufio.NewScanner(file)
	scanner.Scan()
	line := scanner.Text()
	fields := strings.Fields(line)

	la := convertStringToFloat(fields[0])

	// get number of cpu cores
	file, err = os.Open("/proc/cpuinfo")
	if err != nil {
		log.Fatal(err)
	}
	defer file.Close()

	scanner = bufio.NewScanner(file)

	cores := 0
	for scanner.Scan() {
		line := scanner.Text()
		if strings.HasPrefix(line, "processor") {
			cores++
		}
	}

	return la / float32(cores) * 100.0
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

func getFileContent(filename string) string {
	file, err := os.Open(filename)
	if err != nil {
		log.Fatal(err)
	}
	defer file.Close()

	scanner := bufio.NewScanner(file)
	scanner.Scan()
	return scanner.Text()
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

/*
func CPUBenchmark() {

}
*/

func main() {
	var genuser string
	// arguments:
	// -jwtsecret <secret>
	flag.StringVar(&jwtSecret, "jwtsecret", "", "JWT secret")
	// -bindaddr <ip:port>
	flag.StringVar(&bindaddr, "bindaddr", ":8080", "Bind address")
	// -noauth
	flag.BoolVar(&noauth, "noauth", false, "Disable authentication")
	// -genuser <username>
	flag.StringVar(&genuser, "genuser", "", "Generate JWT token for username")

	flag.Parse()

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

	http.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		if !verifyAuth(w, r) {
			return
		}
		http.ServeFile(w, r, "index.html")
	})

	// login.html
	http.HandleFunc("/login.html", func(w http.ResponseWriter, r *http.Request) {
		http.ServeFile(w, r, "login.html")
	})

	http.HandleFunc("/api/sysinfo", func(w http.ResponseWriter, r *http.Request) {
		if !verifyAuth(w, r) {
			return
		}
		handlerSysinfo(w, r)
	})

	// /api/terminate?ifname=<ifname>
	http.HandleFunc("/api/terminate", func(w http.ResponseWriter, r *http.Request) {
		if !verifyAuth(w, r) {
			return
		}
		handleTerm(w, r)
	})

	// /live?ifname=<ifname>
	http.HandleFunc("/live", func(w http.ResponseWriter, r *http.Request) {
		if !verifyAuth(w, r) {
			return
		}

		handleLive(w, r)
	})

	// /api/stat?ifname=' + ifname);
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

	log.Fatal(http.ListenAndServe(bindaddr, nil))
}
