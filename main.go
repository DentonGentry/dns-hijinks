package main

import (
	"fmt"
	"log"

	"github.com/miekg/dns"
)

func getResponse(requestMsg *dns.Msg) (*dns.Msg, error) {
	responseMsg := new(dns.Msg)
	if len(requestMsg.Question) == 0 {
		return responseMsg, nil
	}
	question := requestMsg.Question[0]
	dnsServer := "8.8.8.8:53"

	switch question.Qtype {
	case dns.TypeAAAA:
		answer, err := processTypeAAAA(dnsServer, question, requestMsg)
		if err != nil {
			return responseMsg, err
		}
		responseMsg.Answer = append(responseMsg.Answer, *answer)

	case dns.TypeA:
		// no answer

	default:
		answer, err := processOtherTypes(dnsServer, &question, requestMsg)
		if err != nil {
			return responseMsg, err
		}
		responseMsg.Answer = append(responseMsg.Answer, *answer)
	}

	return responseMsg, nil
}

func processOtherTypes(dnsServer string, q *dns.Question, requestMsg *dns.Msg) (*dns.RR, error) {
	queryMsg := new(dns.Msg)
	requestMsg.CopyTo(queryMsg)
	queryMsg.Question = []dns.Question{*q}

	msg, err := lookup(dnsServer, queryMsg)
	if err != nil {
		return nil, err
	}

	if len(msg.Answer) > 0 {
		return &msg.Answer[0], nil
	}
	return nil, fmt.Errorf("not found")
}

func processTypeAAAA(dnsServer string, q dns.Question, requestMsg *dns.Msg) (*dns.RR, error) {
	queryMsg := new(dns.Msg)
	requestMsg.CopyTo(queryMsg)
	queryMsg.Question = []dns.Question{q}
	queryMsg.Question[0].Qtype = dns.TypeA

	msg, err := lookup(dnsServer, queryMsg)
	if err != nil {
		return nil, err
	}

	if len(msg.Answer) == 0 {
		return nil, fmt.Errorf("not found")
	}

	// wrap IPv4 address for 4via6
	a, ok := msg.Answer[0].(*dns.A)
	if !ok {
		return &msg.Answer[0], nil
	}

	via6 := "fd7a:115c:a1e0:b1a:0:fe:" + a.A.String()
	rr, err := dns.NewRR(fmt.Sprintf("%s 120 IN AAAA %s", q.Name, via6))
	if err != nil {
		return nil, err
	}

	return &rr, nil
}

func lookup(server string, m *dns.Msg) (*dns.Msg, error) {
	dnsClient := new(dns.Client)
	dnsClient.Net = "udp"
	response, _, err := dnsClient.Exchange(m, server)
	if err != nil {
		return nil, err
	}

	return response, nil
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
