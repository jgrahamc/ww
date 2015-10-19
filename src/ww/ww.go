// ww watches the whois record for a zone and reports any differences via
// email
//
// Copyright (c) 2014 John Graham-Cumming
//
// How to use:
//
// 1. Pick the zone to be tested. We'll use example.com
//
// 2. Pick the whois server that you are using. We'll use
// whois.networksolutions.com
//
// 3. Do 'whois -h whois.networksolutions.com example.com > expected-output'
// to record the expected output from whois for that zone in a file.
//
// 4. Run ww: 'ww -expect expected-output -zone example.com -whois
// whois.networksolutions.com:43 -to alert@example.com'

package main

import (
	"bytes"
	"flag"
	"fmt"
	"io/ioutil"
	"log"
	"net"
	"net/smtp"
	"regexp"
	"strings"
	"time"
)

// This regular expression is used to find 'fields' in the whois output

var fieldRe = regexp.MustCompile(`^((?:[A-Z][A-Za-z]+ ?)+):(.*)$`)

// keys takes a map[string]X and flattens the keys into a space-separated
// string
func keys(m map[string]bool) (s string) {
	for k := range m {
		s += k
		s += " "
	}
	return
}

// report adds a message (printf style) to message to be emailed if there are
// any changes
func report(msg *string, format string, values... interface{}) {
	add := fmt.Sprintf(format + "\n", values...)
	log.Printf(add)
	*msg += add
}

// sendReport sends any report of whois differences via email
func sendReport(server, from, zone, msg string, to []string) {
	if msg == "" {
		return
	}

	t := strings.Join(to, ", ")
	header := fmt.Sprintf(`From: %s
To: %s
Date: %s
Subject: WARNING! Change in %s whois record

`, from, t, time.Now().Format(time.RFC822Z), zone)

	msg = header + msg
	err := smtp.SendMail(server, nil, from, to, []byte(msg))
	if err != nil {
		log.Printf("Error sending message from %s to %s via %s: %s",
			from, t, server, err)
	}
}

// split takes the output of whois and splits by lines and then finds the Foo:
// Bar fields and adds them to a map. Each entry in the map is a map itself so
// that a field can appear more than once.
func split(b []byte) map[string]map[string]bool {
	fields := make(map[string]map[string]bool)

	lines := bytes.Split(b, []byte("\n"))
	for _, l := range lines {
		m := fieldRe.FindSubmatch(l)
		if m != nil {
			k := string(m[1])
			if _, ok := fields[k]; !ok {
				fields[k] = make(map[string]bool)
			}
			v := string(bytes.TrimSpace(m[2]))
			fields[k][v] = true
		}
	}

	return fields
}
func main() {
	whois := flag.String("whois", "whois.networksolutions.com:43",
		"whois server host:port")
    expect := flag.String("expect", "",
		"Name of file containing expected output from whois")
	zone := flag.String("zone", "",
		"The zone to check in whois")
	from := flag.String("from", "",
		"Email addresses to send from")
	to := flag.String("to", "",
		"Comma-separated list of email addresses to send to")
	smtpServer := flag.String("smtp", "gmail-smtp-in.l.google.com:25", 
		"Address of SMTP server to use (host:port)")
	flag.Parse()

	if *expect == "" {
		fmt.Printf("The -expect parameter is required\n")
		return
	}
	if *to == "" {
		fmt.Printf("The -to parameter is required\n")
		return
	}
	if *from == "" {
		fmt.Printf("The -from parameter is required\n")
		return
	}
	if *zone == "" {
		fmt.Printf("The -zone parameter is required\n")
		return
	}

	_, _, err := net.SplitHostPort(*whois)
	if err != nil {
		fmt.Printf("The -whois parameter must have format host:port: %s\n",
			err)
		return
	}
	_, _, err = net.SplitHostPort(*smtpServer)
	if err != nil {
		fmt.Printf("The -smtp parameter must have format host:port: %s\n",
			err)
		return
	}

	recipients := strings.Split(*to, ",")

	expected, err := ioutil.ReadFile(*expect)
	if err != nil {
		fmt.Printf("Error reading file %s: %s\n", *expect, err)
		return
	}
	fields := split(expected)
	log.Printf("Loaded %d fields from %s", len(fields), *expect)

	c, err := net.Dial("tcp", *whois)
	if err != nil {
		log.Printf("Error reading from %s: %s", *whois, err)
		return
	}
	
	fmt.Fprintf(c, "%s\r\n", *zone)
	response, err := ioutil.ReadAll(c)
	c.Close()
	if err != nil {
		log.Printf("Error connecting to %s: %s", *whois, err)
		return
	}

	got := split(response)
			
	msg := new(string)
	
	if len(fields) != len(got) {
		report(msg, "Field count different: %d %d", len(fields),
			len(got))
	}
	
	for k, m0 := range fields {
		if m1, ok := got[k]; !ok {
			report(msg, "Field %s required but missing", k)
		} else {
			for v := range m0 {
				if _, ok = m1[v]; !ok {
					report(msg, 
						"Field %s expected value [%s] missing",
						k, v)
				}
			}
			
			for v := range m1 {
				if _, ok = m0[v]; !ok {
					report(msg, "Field %s extra value [%s]",
						k, v)
				}
			}
		}
	}
	
	for k, v := range got {
		if _, ok := fields[k]; !ok {
			report(msg, "Extra field %s with value %s", k, keys(v))
		}
	}
	
	sendReport(*smtpServer, *from, *zone, *msg, recipients)
}
