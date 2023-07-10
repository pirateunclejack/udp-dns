package dns_request

import (
	"bytes"
	"encoding/binary"
	"fmt"
	"log"
	"net"
	"strings"
)

type Header struct {
	ID uint16
	Flags uint16
	QuestionCount uint16
	AnswerCount uint16
	AuthorityCount uint16
	AdditionalCount uint16
}

func (header *Header) SetFlag(qr, opcode, aa, tc, rd, ra, rcode uint16){
	header.Flags = qr << 15 + opcode << 11 + aa << 10 + tc << 9 + rd << 8 + ra << 7 + rcode
}

type Query struct {
	QuestionType uint16
	QeustionClass uint16
}

func ParseDomainName(domain string) []byte {
	// cut domain by . save content and length to byte slice
	// content: length + content, length + content.... end with 0x00
	var (
		buffer bytes.Buffer
		segments = strings.Split(domain, ".")
	)
	for _, seg := range segments {
		binary.Write(&buffer, binary.LittleEndian, byte(len(seg)))
		binary .Write(&buffer, binary.LittleEndian, []byte(seg))
	}

	buffer.Write([]byte{0})
	return buffer.Bytes()
}

func DigDomain(dnsServerAddr, domain string) (querys, answers string){
	header := Header{}
	header.AnswerCount = 1
	header.ID = 0xFF
	header.AdditionalCount = 0
	header.SetFlag(0, 0, 0, 0, 0, 0, 0)
	header.AuthorityCount = 0
	header.QuestionCount = 1

	query := Query {
		QuestionType: 1,
		QeustionClass: 1,
	}

	var (
		conn net.Conn
		err error
		buffer bytes.Buffer

	)

	binary.Write(&buffer, binary.BigEndian, header)
	binary.Write(&buffer, binary.BigEndian, ParseDomainName(domain))
	binary.Write(&buffer, binary.BigEndian, query)

	if conn, err = net.Dial("udp", dnsServerAddr); err != nil {
		log.Println(err)
		return
	}
	defer conn.Close()

	if _, err = conn.Write(buffer.Bytes()); err != nil {
		log.Println(err)
		return
	}
	bytes := make([]byte, 1024)
	n, err := conn.Read(bytes)
	if err != nil {
		log.Println(err)
		return
	}

	bytes = bytes[:n]
	querys_slice, answers_slice := dnsResponseDecode(bytes)
	querys = fmt.Sprint(querys_slice)
	answers = fmt.Sprint(answers_slice)
	return querys, answers
}

func dnsResponseDecode(res []byte) (querys, answers []string){
	header := res[:12]
	queryNum := uint16(header[4]) << 8  + uint16(header[5])
	answerNum := uint16(header[6]) << 8  + uint16(header[7])
	data := res[12:]
	index := 0
	querysBytes := make([][]byte, queryNum)
	answersBytes := make([][]byte, answerNum)

	for i := 0; i < int(queryNum); i++ {
		start := index
		l := 0
		for {
			l = int(data[index])
			if l == 0 {
				break
			}
			index += 1 + l
		}
		index += 4
		querysBytes[i] = data[start: index + 1 ]
		index += 1
	}

	if answerNum != 0 {
		for i := 0; i < int(answerNum); i++ {
			start := index
			nums := 2 + 2 + 2 + 4 + 2
			datalenIndex := start + 2 + 2 + 2 + 4
			dataLength := int(uint16(data[datalenIndex]) << 8 + uint16(data[datalenIndex+1]))
			index = start + nums - 1 + dataLength
			answersBytes[i] = data[start : index+1]
			index += 1
		}
	}
	// fmt.Println(querysBytes, answersBytes)
	querys = make([]string, queryNum)
	for i, bytes := range querysBytes {
		querys[i] = getQuery(bytes)
	}
	answers = make([]string, answerNum)
	for i, bytes := range answersBytes {
		answers[i] = getAnswerString(bytes)
	}

	return
}

func getQuery(bytes []byte) string {
	return getDomain(bytes)
}

func getAnswerString(bytes []byte) string {
	typ := uint16(bytes[2]) << 8 + uint16(bytes[3])
	datalenIndex := 2 + 2 + 2 + 4
	dataLength := int(uint16(bytes[datalenIndex]) << 8 + uint16(bytes[datalenIndex+1]))
	address := bytes[datalenIndex + 2:datalenIndex + 2 + dataLength]
	if typ == 1 {
		return fmt.Sprintf("%d.%d.%d.%d", address[0],address[1],address[2],address[3])
	} else if typ == 5 {
		return getDomain(bytes)
	} else {
		return ""
	}
}

func getDomain (bytes []byte) string {
	domain := ""
	index := 0
	l := 0
	for {
		if index >= len(bytes) {
			break
		}
		l = int(bytes[index])
		if l == 0 {
			break
		}

		if index +1 +l > len(bytes) {

			domain += string(bytes[index+1:]) + "."
		} else {
			domain += string(bytes[index+1:index+1+l]) + "."
		}
		index += 1 + l
	}
	domain = strings.Trim(domain, ".")
	return domain
}

