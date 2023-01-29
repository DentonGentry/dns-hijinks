package main

import (
	"fmt"
	"log"
	"math/rand"

	"github.com/miekg/dns"
)

var (
	ROOT_NAMESERVERS = []string{
		"198.41.0.4", "199.9.14.201", "192.33.4.12", "199.7.91.13", "192.203.230.10",
		"192.5.5.241", "192.112.36.4", "198.97.190.53", "192.36.148.17", "192.58.128.30",
		"193.0.14.129", "199.7.83.42", "202.12.27.33",
	}
)

// from https://gist.github.com/timothyandrew/c5d13b5957f1323ea775705ff9374ff1
func resolve(name string) ([]dns.RR, error) {
	nameserver := ROOT_NAMESERVERS[rand.Intn(len(ROOT_NAMESERVERS))]
	c := new(dns.Client)

	for {
		// Prepare a message asking for an A record (an IP address) for `name`
		m := new(dns.Msg)
		m.SetQuestion(dns.Fqdn(name), dns.TypeA)

		// Send the DNS request to the IP in `nameserver`
		resp, _, err := c.Exchange(m, fmt.Sprintf("%s:53", nameserver))
		if err != nil {
			return nil, err
		}

		if len(resp.Answer) > 0 {
			// If an ANSWER SECTION exists and contains a CNAME, recurse
			if cname, ok := resp.Answer[0].(*dns.CNAME); ok {
				return resolve(cname.Target)
			}

			// If an ANSWER SECTION exists, we're done
			return resp.Answer, nil
		}

		// If the ADDITIONAL SECTION is empty and the AUTHORITY SECTION is not, resolve
		// one of the names in the AUTHORITY SECTION and have that be the nameserver
		if len(resp.Extra) == 0 && len(resp.Ns) != 0 {
			ns := resp.Ns[0].(*dns.NS)
			nsIP, err := resolve(ns.Ns)
			if err != nil {
				return nil, fmt.Errorf("break in the chain")
			}
			nameserver = nsIP[0].(*dns.A).A.String()
		} else {
			// If an ADDITIONAL SECTION exists, look in it for an A record for the
			// next-level nameserver. If one doesn't exist, we have to error out
			found := false
			for _, rr := range resp.Extra {
				record, ok := rr.(*dns.A)
				if ok {
					nameserver = record.A.String()
					found = true
					break
				}
			}
			if !found {
				return nil, fmt.Errorf("break in the chain")
			}
		}

		// ... and recurse!
	}
}

func processTypeAAAA(q *dns.Question, requestMsg *dns.Msg) ([]dns.RR, error) {
	answers, err := resolve(q.Name)
	if err != nil {
		return nil, err
	}
	if len(answers) == 0 {
		return nil, fmt.Errorf("not found")
	}

	ret := []dns.RR{}
	for _, answer := range answers {
		// wrap IPv4 address for 4via6
		a, ok := answer.(*dns.A)
		if !ok {
			continue
		}

		via6 := "fd7a:115c:a1e0:b1a:0:fe:" + a.A.String()
		rr, err := dns.NewRR(fmt.Sprintf("%s 120 IN AAAA %s", q.Name, via6))
		if err != nil {
			continue
		}

		ret = append(ret, rr)
	}

	return ret, nil
}

func processOther(q *dns.Question, requestMsg *dns.Msg) ([]dns.RR, error) {
	dnsServer := "8.8.8.8:53"
	queryMsg := new(dns.Msg)
	requestMsg.CopyTo(queryMsg)
	queryMsg.Question = []dns.Question{*q}

	dnsClient := new(dns.Client)
	dnsClient.Net = "udp"
	responseMsg, _, err := dnsClient.Exchange(queryMsg, dnsServer)
	if err != nil {
		return nil, err
	}

	if len(responseMsg.Answer) > 0 {
		return responseMsg.Answer, nil
	}
	return nil, fmt.Errorf("not found")
}

func getResponse(requestMsg *dns.Msg) (*dns.Msg, error) {
	responseMsg := new(dns.Msg)
	if len(requestMsg.Question) == 0 {
		return responseMsg, nil
	}
	question := requestMsg.Question[0]

	switch question.Qtype {
	case dns.TypeAAAA:
		answers, err := processTypeAAAA(&question, requestMsg)
		if err != nil {
			return responseMsg, err
		}
		for _, answer := range answers {
			responseMsg.Answer = append(responseMsg.Answer, answer)
		}

	case dns.TypeA:
		// no answer

	default:
		answers, err := processOther(&question, requestMsg)
		if err != nil {
			return responseMsg, err
		}
		for _, answer := range answers {
			responseMsg.Answer = append(responseMsg.Answer, answer)
		}
	}

	return responseMsg, nil
}

func main() {
	dns.HandleFunc(".", func(w dns.ResponseWriter, r *dns.Msg) {
		switch r.Opcode {
		case dns.OpcodeQuery:
			m, err := getResponse(r)
			if err != nil {
				log.Printf("Failed lookup for %s with error: %s\n", r, err.Error())
			}
			m.SetReply(r)
			w.WriteMsg(m)
		}
	})

	server := &dns.Server{Addr: "100.127.188.88:53", Net: "udp"}
	err := server.ListenAndServe()
	if err != nil {
		log.Printf("Failed to start server: %s\n ", err.Error())
	}
}
