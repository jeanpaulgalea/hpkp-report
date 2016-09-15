package main

import (
	"crypto/sha256"
	"crypto/x509"
	"database/sql"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"
	"github.com/go-sql-driver/mysql"
	"log"
	"net"
	"net/http"
	"regexp"
	"strings"
	"time"
)

var db *sql.DB

type report struct {
	DateTime                  time.Time `json:"date-time"`
	EffectiveExpirationDate   time.Time `json:"effective-expiration-date"`
	Hostname                  string    `json:"hostname"`
	NotedHostname             string    `json:"noted-hostname"`
	Port                      uint16    `json:"port"`
	IncludeSubdomains         bool      `json:"include-subdomains"`
	ServedCertificateChain    []string  `json:"served-certificate-chain"`
	ValidatedCertificateChain []string  `json:"validated-certificate-chain"`
	KnownPins                 []string  `json:"known-pins"`
}

type Certificate struct {
	PEM      string
	Pin      string
	Position int
}

func main() {
	var err error
	db, err = sql.Open("mysql", "root:abcd@/hpkp")
	if err != nil {
		panic(err.Error())
	}
	defer db.Close()

	err = db.Ping()
	if err != nil {
		panic(err.Error())
	}

	http.HandleFunc("/", ReceiveReport)
	log.Fatal(http.ListenAndServe(":8080", nil))
}

func ReceiveReport(w http.ResponseWriter, req *http.Request) {
	if req.Method != "POST" {
		w.WriteHeader(400)
		return
	}

	decoder := json.NewDecoder(req.Body)
	var r report
	err := decoder.Decode(&r)
	if err != nil {
		w.WriteHeader(400)
		return
	}

	ip := RequestIP(req)
	user_agent := req.Header.Get("User-Agent")

	kpins, err := KnownPins(r.KnownPins)
	if err != nil {
		w.WriteHeader(400)
		return
	}

	certs_s, err := CertificateChain(r.ServedCertificateChain)
	if err != nil {
		w.WriteHeader(400)
		return
	}
	certs_v, err := CertificateChain(r.ValidatedCertificateChain)
	if err != nil {
		w.WriteHeader(400)
		return
	}

	err = violation(r, ip, user_agent, kpins, certs_s, certs_v)
	if err != nil {
		fmt.Println(err.Error())
	}
}

func RequestIP(req *http.Request) string {
	s := req.Header.Get("X-Forwarded-For")
	if s == "" {
		s = req.RemoteAddr
	}

	// drop port if necessary
	host, _, err := net.SplitHostPort(s)
	if err == nil {
		s = host
	}

	ip := net.ParseIP(s)
	if ip != nil {
		return ip.String()
	}
	return ""
}

func KnownPins(pins []string) ([]string, error) {
	re := regexp.MustCompile("\\Apin-sha256=(\"[^\"]+\"|'[^']+')\\z")

	p := make([]string, 0, len(pins))

	for _, pin := range pins {
		r := re.FindStringSubmatch(pin)
		if r == nil {
			return p, errors.New("")
		}

		s := strings.Trim(r[1], "\"'")

		data, err := base64.StdEncoding.DecodeString(s)
		if err != nil {
			return p, errors.New("")
		}
		if len(data) != 32 {
			return p, errors.New("")
		}

		p = append(p, s)
	}

	return p, nil
}

func CertificateChain(PEMCerts []string) ([]Certificate, error) {
	c := make([]Certificate, 0, len(PEMCerts))

	for i, PEMCert := range PEMCerts {
		block, _ := pem.Decode([]byte(PEMCert))
		if block == nil {
			return c, errors.New("")
		}
		x509cert, err := x509.ParseCertificate(block.Bytes)
		if err != nil {
			return c, errors.New("")
		}
		p, err := PKPSHA256Hash(x509cert)
		if err != nil {
			return c, errors.New("")
		}

		c = append(c, Certificate{PEM: PEMCert, Pin: p, Position: i})
	}

	return c, nil
}

func PKPSHA256Hash(cert *x509.Certificate) (string, error) {
	var s string
	var b [32]byte

	der, err := x509.MarshalPKIXPublicKey(cert.PublicKey)
	if err != nil {
		return s, errors.New("")
	}

	b = sha256.Sum256(der)
	s = base64.StdEncoding.EncodeToString(b[:])

	return s, nil
}

func violation(r report, ip string, user_agent string, kpins []string, certs_s_chain []Certificate, certs_v_chain []Certificate) error {
	tx, err := db.Begin()
	if err != nil {
		return err
	}

	report_id, err := db_report(tx, r, ip, user_agent)
	if err != nil {
		tx.Rollback()
		return err
	}
	err = pins(tx, report_id, kpins)
	if err != nil {
		tx.Rollback()
		return err
	}
	err = certs_s(tx, report_id, certs_s_chain)
	if err != nil {
		tx.Rollback()
		return err
	}
	err = certs_v(tx, report_id, certs_v_chain)
	if err != nil {
		tx.Rollback()
		return err
	}

	return tx.Commit()
}

func db_report(tx *sql.Tx, r report, request_ip string, user_agent string) (int64, error) {
	var report_id int64

	date_time := r.DateTime.Format("2006-01-02 15:04:05")
	effective_expiration_date := r.EffectiveExpirationDate.Format("2006-01-02 15:04:05")
	include_subdomains := 0
	if r.IncludeSubdomains == true {
		include_subdomains = 1
	}

	res, err := tx.Exec("INSERT INTO reports (created_at, request_ip, user_agent, date_time, effective_expiration_date, hostname, noted_hostname, port, include_subdomains) VALUES (UTC_TIMESTAMP(), ?, ?, ?, ?, ?, ?, ?, ?)", request_ip, user_agent, date_time, effective_expiration_date, r.Hostname, r.NotedHostname, r.Port, include_subdomains)
	if err != nil {
		return report_id, errors.New("1")
	}
	report_id, err = res.LastInsertId()
	if err != nil {
		return report_id, errors.New("2")
	}

	return report_id, nil
}

func pins(tx *sql.Tx, report_id int64, pins []string) error {
	var pin_id int

	for _, pin := range pins {
		_, err := tx.Exec("INSERT INTO pins (pin) VALUES (?)", pin)
		if err != nil {
			if mysqlError, ok := err.(*mysql.MySQLError); ok {
				if mysqlError.Number == 1062 {
					err = nil
				}
			}
		}
		if err != nil {
			return err
		}

		err = tx.QueryRow("SELECT id FROM pins WHERE pin = ?", pin).Scan(&pin_id)
		if err != nil {
			return err
		}

		_, err = tx.Exec("INSERT INTO report_pins (report_id, pin_id) VALUES (?, ?)", report_id, pin_id)
		if err != nil {
			if mysqlError, ok := err.(*mysql.MySQLError); ok {
				// ignore duplicates pin-sha256="".
				// RFC doesn't state anything about this (so allowed?),
				//	but doesn't make any sense to store this information.
				if mysqlError.Number == 1062 {
					continue
				}
			}
			return err
		}
	}

	return nil
}

func certs_s(tx *sql.Tx, report_id int64, certs []Certificate) error {
	return db_certs("s", tx, report_id, certs)
}
func certs_v(tx *sql.Tx, report_id int64, certs []Certificate) error {
	return db_certs("v", tx, report_id, certs)
}

func db_certs(t string, tx *sql.Tx, report_id int64, certs []Certificate) error {
	var cert_id int

	for _, cert := range certs {
		_, err := tx.Exec("INSERT INTO certs (cert, pin) VALUES (?, ?)", cert.PEM, cert.Pin)
		if err != nil {
			if mysqlError, ok := err.(*mysql.MySQLError); ok {
				if mysqlError.Number == 1062 {
					err = nil
				}
			}
		}
		if err != nil {
			return err
		}

		err = tx.QueryRow("SELECT id FROM certs WHERE pin = ?", cert.Pin).Scan(&cert_id)
		if err != nil {
			return err
		}

		var query string
		if t == "s" {
			query = "INSERT INTO report_s_chain (report_id, cert_id, position) VALUES (?,?,?)"
		} else {
			query = "INSERT INTO report_v_chain (report_id, cert_id, position) VALUES (?,?,?)"
		}

		_, err = tx.Exec(query, report_id, cert_id, cert.Position)
		if err != nil {
			return err
		}
	}

	return nil
}
