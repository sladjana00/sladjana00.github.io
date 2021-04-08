package main

import (
	"bytes"
	"context"
	"encoding/csv"
	"encoding/json"
	"fmt"
	"log"
	"net"
	"net/http"
	"os"
	"os/exec"
	"path"
	"path/filepath"
	"regexp"
	"runtime"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/360EntSecGroup-Skylar/excelize"

	//"github.com/Ullaakut/nmap"
	"golang.org/x/sync/semaphore"

	"./3rdparty/go-powershell/backend"

	ps "./3rdparty/go-powershell"
)

var debug bool = true
var timeStartScan time.Time
var timeEndScan time.Time

var outFolder string

var ADCsvResults [][]string
var ADTCPOpenPorts []string
var LocalCsvResults [][]string
var LocalTCPOpenPorts []string

var totalHostsAD int
var nbrAccessibleHostsAD int
var nbrAccessibleHostsAsServerAD int
var nbrAccessibleHostsAsClientAD int
var ADOperatingSystems []string

var nbrServerWithOpenPort int = 0
var nbrTotalServer int = 1
var nbrClientWithOpenPort int = 0
var nbrTotalClient int = 1

var totalHostsLoc int
var nbrAccessibleHostsLoc int

var CSVAdAssetsFileName string
var CSVAdNetworkFileName string
var CSVLocalAssetsFileName string
var CSVLocalNetworkFileName string

type DataIPOpenPort struct {
	FQDN                   string `json:"fqdn"`
	Hostname               string `json:"hostname"`
	Type                   string `json:"type"`
	Ip                     string `json:"ip"`
	ComputerName           string `json:"computername"`
	OperatingSystem        string `json:"operatingsystem"`
	OperatingSystemVersion string `json:"operatingsystemversion"`
	DistinguishedName      string `json:"distinguishedname"`
	TCPPorts               string `json:"tcpports"`
	Time                   string `json:"time"`
}

var IPData []DataIPOpenPort
var IP_Level1_array []string
var IP_Level2_array []string
var IP_Level3_array []string

type ItemLvl3 struct {
	IpLvl3  string           `json:"ip_lvl3"`
	Clients []DataIPOpenPort `json:"clients"`
	Servers []DataIPOpenPort `json:"servers"`
}

type ItemLvl2 struct {
	IpLvl2   string     `json:"ip_lvl2"`
	SonsLvl2 []ItemLvl3 `json:"sons_lev_2"`
}

type ItemLvl1 struct {
	IpLvl1   string     `json:"ip_lvl1"`
	SonsLvl1 []ItemLvl2 `json:"sons_lev_1"`
}

type TreeIP struct {
	Content []ItemLvl1 `json:"content"`
}

var treeIP TreeIP

type OsLvl1 struct {
	OsName   string           `json:"os_name`
	SonsLvl1 []DataIPOpenPort `json:"sons_lev_1`
}

type TreeOS struct {
	Content []OsLvl1 `json:"content"`
}

var treeOS TreeOS

type PortsLvl1 struct {
	Port    string           `json:"port`
	Clients []DataIPOpenPort `json:"clients`
	Servers []DataIPOpenPort `json:"servers`
}

type TreePorts struct {
	Content []PortsLvl1 `json:"content"`
}

var treePorts TreePorts

var UDPPorts = []int{
	7, 9, 17, 19, 49, 53, 67, 68, 69, 80,
	88, 111, 120, 123, 135, 136, 137, 138, 139, 158,
	161, 162, 177, 427, 443, 445, 497, 500, 514, 515,
	518, 520, 593, 623, 626, 631, 996, 997, 998, 999,
	1022, 1023, 1025, 1026, 1027, 1028, 1029, 1030, 1433, 1434,
	1645, 1646, 1701, 1718, 1719, 1812, 1813, 1900, 2000, 2048,
	2049, 2222, 2223, 3283, 3456, 3703, 4444, 4500, 5000, 5060,
	5353, 5632, 9200, 10000, 17185, 20031, 30718, 31337, 32768, 32769,
	32771, 32815, 33281, 49152, 49153, 49154, 49156, 49181, 49182, 49185,
	49186, 49188, 49190, 49191, 49192, 49133, 49194, 49200, 49201, 65024,
}

var TCPPorts = []int{
	7, 9, 13, 21, 22, 23, 25, 26, 37, 53,
	79, 80, 81, 88, 106, 110, 111, 113, 119, 135,
	139, 143, 144, 179, 199, 389, 427, 443, 444, 445,
	465, 513, 514, 515, 543, 544, 548, 554, 587, 631,
	646, 873, 990, 993, 995, 1025, 1026, 1027, 1028, 1029,
	1110, 1433, 1720, 1723, 1755, 1900, 2000, 2001, 2049, 2121,
	2717, 3000, 3128, 3306, 3389, 3986, 4899, 5000, 5009, 5051,
	5060, 5101, 5190, 5357, 5432, 5631, 5666, 5800, 5900, 6000,
	6001, 6646, 7070, 8000, 8008, 8009, 8080, 8081, 8443, 8888,
	9100, 9999, 10000, 32768, 49152, 49153, 49154, 49155, 49156, 49157,
}

var ServicePorts = []string{
	"echo", "discard", "daytime", "ftp", "ssh", "telnet", "smtp", " ", "time", "domain",
	"vettcp", "http", "http", "kerberos", "3com-tsmux", "pop3", "sunrpc", "auth", "nntp", "epmap",
	"netbios-ssn", "imap", "uma", "bgp", "smux", "ldap", "svrloc", "https", "snpp", "microsoft-ds",
	"urd/submission/igmpv3lite", "login/who", "shell/syslog", "printer", "klogin", "kshell", "afpovertcp", "rtsp", "submission", "ipp",
	"ldp", "rsync", "ftps", "imaps", "pop3s", "blackjack", "cap", "6a44", " ", "solid-mux",
	"webadmstart/nfsd-keepalive", "ms-sql-s", "h323hostcall", "pptp", "ms-streaming", "ssdp", "cisco-sccp", "dc/wizard", "shilp/nfs", "scientia-ssdb",
	"pn-requester", "hbci/remoteware-cl", "ndl-aas", "mysql", "ms-wbt-server", "mapper-ws-ethd", "radmin-port", "commplex-main", "winfs", "ita-agent",
	"sip", "talarian-tcp/talarian-udp", "aol", "wsdapi", "postgresql", "pcanywheredata", "nrpe", " ", "rfb", "x11",
	"x11", " ", "arcp", "irdmi", "http-alt", "nvme-disc", "http-alt", "sunproxyadmin", "pcsync-https", "ddi-udp-1",
	"hp-pdl-datastr", "distinct", "ndmp", "filenet-tms", "/Titan Quest", "ANTLR", "Xsan", " ", "Azureus", " ",
}

type ScanResult struct {
	IP       string
	Protocol string
	Port     int
	State    string
}

type PortScanner struct {
	ip   string
	lock *semaphore.Weighted
}

type ComputerInfo struct {
	Name              string
	OS                string
	OSVersion         string
	DNSHostname       string
	PWLastSet         string
	DistinguishedName string
}

// PowerShell struct
type PowerShell struct {
	powerShell string
}

// New create new session
func New() *PowerShell {
	ps, _ := exec.LookPath("powershell.exe")
	return &PowerShell{
		powerShell: ps,
	}
}

func (p *PowerShell) execute(args ...string) (stdOut string, stdErr string, err error) {
	args = append([]string{"-NoProfile", "-NonInteractive"}, args...)
	cmd := exec.Command(p.powerShell, args...)

	var stdout bytes.Buffer
	var stderr bytes.Buffer
	cmd.Stdout = &stdout
	cmd.Stderr = &stderr

	err = cmd.Run()
	stdOut, stdErr = stdout.String(), stderr.String()
	return
}

func extractIPSubnetMask() []string {

	var cidrLIST []string

	ifaces, _ := net.Interfaces()

	for _, i := range ifaces {

		addrs, err := i.Addrs()
		if err != nil {
			fmt.Println("Interface has no address")
			os.Exit(-1)
		}

		for _, addr := range addrs {
			var ip net.IP

			switch v := addr.(type) {
			case *net.IPNet:
				ip = v.IP
			case *net.IPAddr:
				ip = v.IP
			}

			if ip == nil {
				continue
			}
			ip = ip.To4()
			if ip == nil {
				continue
			}

			cidrLIST = append(cidrLIST, addr.String())
		}
	}

	return cidrLIST
}

func incIP(ip net.IP) {

	for j := len(ip) - 1; j >= 0; j-- {
		ip[j]++
		if ip[j] > 0 {
			break
		}
	}
}

type PingResult struct {
	IP     string
	Status string
}

func WordCount(value string) int {
	// Match non-space character sequences.
	re := regexp.MustCompile(`[\S]+`)

	// Find all matches and return count.
	results := re.FindAllString(value, -1)
	return len(results)
}

func isHostNameReachable(hostname string, result chan PingResult, retries int) {

	var outputPing string

	switch runtime.GOOS {
	case "windows":
		outputPing, _ = executeShell("ping", []string{"-n", "5", hostname})
	default:
		outputPing, _ = executeShell("ping", []string{"-c", "5", hostname})
	}

	if len(outputPing) < 5 ||
		strings.Contains(strings.ToLower(outputPing), "request timed out.") ||
		strings.Contains(strings.ToLower(outputPing), "destination host unreachable") ||
		strings.Contains(strings.ToLower(outputPing), "received = 0") ||
		strings.Contains(strings.ToLower(outputPing), "host is down") ||
		strings.Contains(strings.ToLower(outputPing), "0 received, 100% packet loss") ||
		strings.Contains(strings.ToLower(outputPing), "0 packets received, 100.0% packet loss") {

		//		fmt.Println(hostname, "is offline, number of trials to connect left ", retries, "/5")

		if retries == 0 {
			if debug {
				fmt.Println(hostname, "is OFFLINE *****************************")
			}

			result <- PingResult{IP: hostname, Status: "OFFLINE"}
			return
		}

		retries--
		isHostNameReachable(hostname, result, retries)

		return
	}

	if debug {
		fmt.Println(hostname, "is ONLINE ******************")
	}

	result <- PingResult{IP: hostname, Status: "ONLINE"}
	return
}

func calculateIP() []string {

	localIPList := extractIPSubnetMask()

	var ips []string

	//localIPList = localIPList[5:6]

	var tmplocalIPList []string

	// Remove localhost 127.0.0.1 from the IP list
	for _, ip := range localIPList {
		if !strings.Contains(ip, "127.0.0.1") && !strings.Contains(ip, "169.254.") {
			tmplocalIPList = append(tmplocalIPList, ip)
		}
	}

	localIPList = tmplocalIPList

	if debug {
		fmt.Println("Local IP Address :", localIPList)
	}

	for _, cidr := range localIPList {
		ip, ipnet, _ := net.ParseCIDR(cidr)

		for ip := ip.Mask(ipnet.Mask); ipnet.Contains(ip); incIP(ip) {

			if !strings.HasSuffix(ip.String(), ".0") && !strings.HasSuffix(ip.String(), ".255") {
				ips = append(ips, ip.String())
			}
		}
	}

	return ips
}

func executePowerShell(command string) (string, error) {

	// choose a backend
	back := &backend.Local{}

	// start a local powershell process
	shell, err := ps.New(back)
	if err != nil {
		panic(err)
	}
	defer shell.Exit()

	// ... and interact with it
	stdout, _, err := shell.Execute(command)

	return stdout, err
}

func executeShell(command string, args []string) (string, error) {

	cmd := exec.Command(command, args...)

	var out bytes.Buffer
	cmd.Stdout = &out
	err := cmd.Run()

	if err != nil {
		//log.Fatal(err)
	}

	return out.String(), err
}

func localSubnet() []string {

	ipList := calculateIP()

	return ipList
}

func machineIsDomainConnected() bool {

	_, err := executeShell("nltest", []string{"/dsgetdc:"})

	if err != nil {
		return false
	}

	if debug {
		fmt.Println("Machine is Connected to Domain Controller!")
	}
	return true
}

func getdomainname(output string) string {

	s := strings.Split(output, "\n")

	var domainName string

	for _, str := range s {
		if strings.Contains(str, "Dom Name") {
			domainName = strings.ReplaceAll(str, "Dom Name:", "")
		}
	}

	// Remove any whitespaces.
	domainName = strings.ReplaceAll(domainName, " ", "")

	return domainName
}

func discoverDomain() string {

	output, err := executePowerShell("nltest /dsgetdc:")

	if err == nil {

		domainName := getdomainname(output)

		return strings.ReplaceAll(domainName, "\r", "")
	}

	return ""
}

func discoverComputers() string {

	cmdShell1 := "$searcher = New-Object DirectoryServices.DirectorySearcher"
	cmdShell2 := "$searcher.Filter = '(objectclass=computer)'"

	cmdShell4 := "$searcher.FindAll().GetEnumerator() | %{$_.Properties.path, $_.Properties.name, $_.Properties.operatingsystem, $_.Properties.operatingsystemversion, $_.Properties.dnshostname, $_.Properties.pwdlastset, $_.Properties.distinguishedname }"

	cmdShell := cmdShell1 + " ; " + cmdShell2 + " ; " + cmdShell4

	clist, _ := executePowerShell(cmdShell)

	var ComputerInfoResult []ComputerInfo
	var ComputerInfoTemp ComputerInfo

	for i, str := range strings.Split(clist, "\n") {

		len := len(ComputerInfoResult)
		str = strings.ReplaceAll(str, "\t", "")
		str = strings.ReplaceAll(str, "\r", "")
		if i == 6*len {
			ComputerInfoTemp.Name = str
		} else if i == (1 + 6*len) {
			ComputerInfoTemp.OS = str
		} else if i == (2 + 6*len) {
			ComputerInfoTemp.OSVersion = str
		} else if i == (3 + 6*len) {
			ComputerInfoTemp.DNSHostname = str
		} else if i == (4 + 6*len) {
			timeStr, _ := executePowerShell("w32tm.exe /ntte " + str)
			ComputerInfoTemp.PWLastSet = strings.ReplaceAll(timeStr, "\n", "")
		} else if i == (5 + 6*len) {
			ComputerInfoTemp.DistinguishedName = str
			ComputerInfoResult = append(ComputerInfoResult, ComputerInfoTemp)
			// Reset tmp variable
			ComputerInfoTemp = ComputerInfo{}
		}
	}

	mapComputerInfoNode := make(map[string]map[string]string)

	for _, cmp := range ComputerInfoResult {
		mapComputerInfoTmp := make(map[string]string)
		mapComputerInfoTmp["name"] = cmp.Name
		mapComputerInfoTmp["operatingsystem"] = cmp.OS
		mapComputerInfoTmp["operatingsystemversion"] = cmp.OSVersion
		mapComputerInfoTmp["dnshostname"] = cmp.DNSHostname
		mapComputerInfoTmp["pwdlastset"] = cmp.PWLastSet
		mapComputerInfoTmp["distinguishedname"] = cmp.DistinguishedName
		if strings.Contains(strings.ToLower(cmp.OS), "server") {
			mapComputerInfoTmp["type"] = "Server"
		} else {
			mapComputerInfoTmp["type"] = "Client"
		}

		mapComputerInfoNode[cmp.Name] = mapComputerInfoTmp
	}

	cListData := make(map[string]map[string]map[string]string)

	cListData["devices"] = mapComputerInfoNode

	mapListInfo, _ := json.Marshal(cListData)
	sData := string(mapListInfo)

	return sData
}

func ScanTCPPort(wg *sync.WaitGroup, ip string, port int, timeout time.Duration, semaphoreChan chan struct{}) {

	semaphoreChan <- struct{}{}

	defer wg.Done()

	target := fmt.Sprintf("%s:%d", ip, port)
	conn, err := net.DialTimeout("tcp", target, timeout)

	var portState string

	if err != nil {
		if strings.Contains(err.Error(), "too many open files") {
			time.Sleep(timeout)
			//wg.Add(1)
			//ScanTCPPort(wg, ip, port, timeout, semaphoreChan)
		} else {
			portState = "closed"
		}
	} else {
		portState = "open"
	}

	conn.Close()

	if portState == "open" {
		fmt.Println(ip, ":", port, "/tcp is ", portState)
	}

	<-semaphoreChan
}

func ScanUDPPort(ip string, port int) bool {

	target := fmt.Sprintf("%s:%d", ip, port)

	serverAddr, err := net.ResolveUDPAddr("udp", target)
	if err != nil {
		return false
	}

	conn, err := net.DialUDP("udp", nil, serverAddr)
	if err != nil {
		return false
	}
	defer conn.Close()

	// Write 3 times to the udp socket and check
	// if there's any kind of error
	errorcount := 0
	for i := 0; i < 3; i++ {
		buf := []byte("0")
		_, err := conn.Write(buf)
		if err != nil {
			errorcount++
		}
	}

	if errorcount > 0 {
		return false
	}
	return true
}

func (ps *PortScanner) StartTCP(portslist []int) {
	wg := sync.WaitGroup{}
	defer wg.Wait()

	wg.Add(1)
	ps.lock.Acquire(context.TODO(), 1)

	semaphoreChan := make(chan struct{}, 2)
	defer close(semaphoreChan)

	var wg2 sync.WaitGroup

	go func(port []int) {
		defer ps.lock.Release(1)
		defer wg.Done()

		for index := 0; index < len(portslist); index++ {

			wg2.Add(1)

			go ScanTCPPort(&wg2, ps.ip, portslist[index], 1*time.Second, semaphoreChan)

		}

		wg2.Wait()

	}(portslist)
}

/*

func (ps *PortScanner) StartTCP(portslist []int, chanresults chan ScanResult) {
	wg := sync.WaitGroup{}
	defer wg.Wait()

	wg.Add(1)
	ps.lock.Acquire(context.TODO(), 1)

	go func(port []int) {
		defer ps.lock.Release(1)
		defer wg.Done()

		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Minute)
		defer cancel()

		sTCPPorts := strconv.Itoa(portslist[0])

		for i := 1; i < len(portslist); i++ {
			sTCPPorts = sTCPPorts + "," + strconv.Itoa(portslist[i])
		}

		scanner, err := nmap.NewScanner(
			nmap.WithTargets(ps.ip),
			nmap.WithPorts(sTCPPorts),
			nmap.WithContext(ctx),
		)

		result, _, err := scanner.Run()

		if err != nil {
			return
		}

		var totalResult []ScanResult

		for _, host := range result.Hosts {
			for _, port := range host.Ports {
				//fmt.Printf("\tHost %s Port %d/%s %s %s\n", host.Addresses[0].String(), port.ID, port.Protocol, port.State, port.Service.Name)
				sPortState := strings.ToLower(port.State.String())
				var result ScanResult = ScanResult{IP: ps.ip, Protocol: "tcp", Port: int(port.ID), State: sPortState}
				fmt.Println(result)
				totalResult = append(totalResult, result)
			}
		}

		for index := 0; index < len(portslist); index++ {
			var resPortFound = getPortResult(portslist[index], totalResult)
			if resPortFound == (ScanResult{}) {
				chanresults <- resPortFound
				continue
			}
			var result ScanResult = ScanResult{IP: ps.ip, Protocol: "tcp", Port: portslist[index], State: "close"}
			chanresults <- result
		}

	}(portslist)
}
*/

func getPortResult(port int, totalResult []ScanResult) ScanResult {

	for _, res := range totalResult {
		if res.Port == port {
			return res
			continue
		}
	}

	return ScanResult{}
}

/*
func (ps *PortScanner) StartUDP(portslist []int, chanresults chan ScanResult) {
	wg := sync.WaitGroup{}
	defer wg.Wait()

	wg.Add(1)
	ps.lock.Acquire(context.TODO(), 1)

	go func(port []int) {
		defer ps.lock.Release(1)
		defer wg.Done()

		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Minute)
		defer cancel()

		sUDPPorts := strconv.Itoa(portslist[0])

		for i := 1; i < len(portslist); i++ {
			sUDPPorts = sUDPPorts + "," + strconv.Itoa(portslist[i])
		}

		scanner, err := nmap.NewScanner(
			nmap.WithTargets(ps.ip),
			nmap.WithPorts(sUDPPorts),
			nmap.WithUDPScan(),
			nmap.WithContext(ctx),
		)

		result, _, err := scanner.Run()

		if err != nil {
			return
		}

		for _, host := range result.Hosts {
			for _, port := range host.Ports {
				fmt.Printf("\tHost %s Port %d/%s %s %s\n", host.Addresses[0].String(), port.ID, port.Protocol, port.State, port.Service.Name)
				sPortState := strings.ToLower(port.State.String())
				var result ScanResult = ScanResult{IP: ps.ip, Protocol: "udp", Port: int(port.ID), State: sPortState}
				fmt.Println(result)
				chanresults <- result
			}
		}

	}(portslist)
}
*/
func runPortScan(ipaddr string, tcpPorts []int, udpPorts []int, slicescanresult *[]ScanResult) {

}

func GetDNByName(name string) string {

	output, _ := executePowerShell("Get-ADUser -Identity " + name + " -Properties *")

	rows := strings.Split(output, "\n")

	for _, str := range rows {
		if strings.Contains(str, "DistinguishedName") {
			DN := strings.ReplaceAll(str, "DistinguishedName :", "")
			return DN
		}
	}

	return ""
}

func getIPByHostname(hostname string) string {
	addrs, _ := net.LookupIP(hostname)
	for _, addr := range addrs {
		if ipv4 := addr.To4(); ipv4 != nil {
			return ipv4.String()
		}
	}

	return ""
}

func getFQDNByHostname(hostname string) string {

	command := "([System.Net.Dns]::GetHostByName(('" + hostname + "'))).Hostname"

	output, err := executePowerShell(command)

	if err == nil {
		return output
	}

	return ""
}

func getComputerInfofromIP(computerList string, IP string) []string {

	var dat map[string]map[string]map[string]interface{}

	if err := json.Unmarshal([]byte(computerList), &dat); err != nil {
		panic(err)
	}

	/*
		FQDN", "Is Managed", "IP Address", "Type", "Name", "Operating System",
		"Operating System Version", "Distinguished Name", "Opened TCP Ports", "Opened UDP Ports", "Rejected TCP Ports"
	*/
	for computerName := range dat["devices"] {

		if computerName == IP {
			DNSHostName := dat["devices"][computerName]["dnshostname"]
			OperatingSystem := dat["devices"][computerName]["operatingsystem"]
			OperatingSystemVersion := dat["devices"][computerName]["operatingsystemversion"]
			FQDN := getFQDNByHostname(computerName)
			DistinguishedName := dat["devices"][computerName]["distinguishedname"]
			Type := dat["devices"][computerName]["type"]
			IP := getIPByHostname(DNSHostName.(string))
			strings.ReplaceAll(IP, "::", ":")

			csvRecord := []string{FQDN, DNSHostName.(string), Type.(string), IP, computerName,
				OperatingSystem.(string), OperatingSystemVersion.(string), DistinguishedName.(string)}

			return csvRecord
		}
	}

	return []string{}
}

func openbrowser(url string) {
	var err error

	switch runtime.GOOS {
	case "linux":
		err = exec.Command("xdg-open", url).Start()
	case "windows":
		err = exec.Command("rundll32", "url.dll,FileProtocolHandler", url).Start()
	case "darwin":
		err = exec.Command("open", url).Start()
	default:
		err = fmt.Errorf("unsupported platform")
	}

	if err != nil {
		log.Fatal(err)
	}
}

func GetDocumentsFolderPath() string {

	documentsPath, _ := executePowerShell("[Environment]::GetFolderPath('myDocuments')")

	documentsPath = strings.ReplaceAll(documentsPath, "\\", "/")
	documentsPath = strings.ReplaceAll(documentsPath, "\r", "")
	documentsPath = strings.ReplaceAll(documentsPath, "\n", "")
	documentsPath = strings.ReplaceAll(documentsPath, "\t", "")

	return documentsPath
}

func displayADAssetsResult(csvrows [][]string) {

	CreateOutputolder()

	fileName := path.Join(outFolder, "AD_Assets_"+time.Now().Format("2006.01.02-15.04.05")+".xlsx")

	fmt.Println("Priting Assets results in ", fileName)
	f := excelize.NewFile()

	fmt.Println("Priting Assets results in ", fileName)

	f.SetCellValue("Sheet1", "A1", "FQDN")
	f.SetCellValue("Sheet1", "B1", "Is Managed")
	f.SetCellValue("Sheet1", "C1", "IP Address")
	f.SetCellValue("Sheet1", "D1", "Type")
	f.SetCellValue("Sheet1", "E1", "Name")
	f.SetCellValue("Sheet1", "F1", "Operating System")
	f.SetCellValue("Sheet1", "G1", "Operating System Version")
	f.SetCellValue("Sheet1", "H1", "Distinguished Name")
	f.SetCellValue("Sheet1", "I1", "Opened TCP Ports")

	for index, row := range csvrows {
		fqdn := row[0]
		managed := "True"
		hosttype := row[2]
		ip := row[3]
		name := row[4]
		os := row[5]
		osversion := row[6]
		distingushed := row[7]
		openports := row[8]

		f.SetCellValue("Sheet1", "A"+strconv.Itoa(index+2), fqdn)
		f.SetCellValue("Sheet1", "B"+strconv.Itoa(index+2), managed)
		f.SetCellValue("Sheet1", "C"+strconv.Itoa(index+2), ip)
		f.SetCellValue("Sheet1", "D"+strconv.Itoa(index+2), hosttype)
		f.SetCellValue("Sheet1", "E"+strconv.Itoa(index+2), name)
		f.SetCellValue("Sheet1", "F"+strconv.Itoa(index+2), os)
		f.SetCellValue("Sheet1", "G"+strconv.Itoa(index+2), osversion)
		f.SetCellValue("Sheet1", "H"+strconv.Itoa(index+2), distingushed)
		f.SetCellValue("Sheet1", "I"+strconv.Itoa(index+2), openports)
	}

	if err := f.SaveAs(fileName); err != nil {
		println(err.Error())
	}

	CSVAdAssetsFileName = fileName
}

func getMaskSize(ip string) int {
	size := 0
	for _, c := range ip {
		if c == '*' {
			size++
		}
	}
	return size
}

func displayADNetworkResult(Tree TreeIP) {

	CreateOutputolder()

	fileName := path.Join(outFolder, "AD_Network_"+time.Now().Format("2006.01.02-15.04.05")+".xlsx")

	fmt.Println("Priting Network results in ", fileName)
	f := excelize.NewFile()

	f.SetCellValue("Sheet1", "A1", "IP Range")
	f.SetCellValue("Sheet1", "B1", "Mask Size")
	f.SetCellValue("Sheet1", "C1", "#Clients")
	f.SetCellValue("Sheet1", "D1", "%Clients")
	f.SetCellValue("Sheet1", "E1", "#Servers")
	f.SetCellValue("Sheet1", "F1", "%Servers")
	f.SetCellValue("Sheet1", "G1", "#Unknown")
	f.SetCellValue("Sheet1", "H1", "%Unknown")
	f.SetCellValue("Sheet1", "I1", "Most Popular")
	f.SetCellValue("Sheet1", "J1", "%Most Popular")
	f.SetCellValue("Sheet1", "K1", "Client hosts")
	f.SetCellValue("Sheet1", "L1", "Server hosts")

	var index int = 1

	for _, elmntLvl1 := range Tree.Content {

		index++
		ip := elmntLvl1.IpLvl1
		mask := getMaskSize(elmntLvl1.IpLvl1)
		nbrClients := 0
		nbrServers := 0
		nbrUnknown := 0
		clientHosts := ""
		serverHosts := ""
		for _, elemtLvl2 := range elmntLvl1.SonsLvl1 {
			for _, elemtLvl3 := range elemtLvl2.SonsLvl2 {
				nbrClients += len(elemtLvl3.Clients)
				nbrServers += len(elemtLvl3.Servers)
				for _, client := range elemtLvl3.Clients {
					clientHosts += client.Hostname + ":" + client.OperatingSystem + ":" + client.OperatingSystemVersion + ","
				}
				for _, server := range elemtLvl3.Servers {
					serverHosts += server.Hostname + ":" + server.OperatingSystem + ":" + server.OperatingSystemVersion + ","
				}
			}
		}
		percClients := (100 * nbrClients) / (nbrClients + nbrServers)
		percServers := 100 - percClients
		mostPopular := ""
		percPopular := 0
		if percClients > percServers {
			mostPopular = "Client"
			percPopular = percClients
		} else {
			mostPopular = "Server"
			percPopular = percServers
		}
		percUnknown := 0
		f.SetCellValue("Sheet1", "A"+strconv.Itoa(index), ip)
		f.SetCellValue("Sheet1", "B"+strconv.Itoa(index), mask)
		f.SetCellValue("Sheet1", "C"+strconv.Itoa(index), nbrClients)
		f.SetCellValue("Sheet1", "D"+strconv.Itoa(index), percClients)
		f.SetCellValue("Sheet1", "E"+strconv.Itoa(index), nbrServers)
		f.SetCellValue("Sheet1", "F"+strconv.Itoa(index), percServers)
		f.SetCellValue("Sheet1", "G"+strconv.Itoa(index), nbrUnknown)
		f.SetCellValue("Sheet1", "H"+strconv.Itoa(index), percUnknown)
		f.SetCellValue("Sheet1", "I"+strconv.Itoa(index), mostPopular)
		f.SetCellValue("Sheet1", "J"+strconv.Itoa(index), percPopular)
		f.SetCellValue("Sheet1", "K"+strconv.Itoa(index), clientHosts)
		f.SetCellValue("Sheet1", "L"+strconv.Itoa(index), serverHosts)

		for _, elemtLvl2 := range elmntLvl1.SonsLvl1 {

			index++
			ip := elemtLvl2.IpLvl2
			mask := getMaskSize(elemtLvl2.IpLvl2)
			nbrClients := 0
			nbrServers := 0
			nbrUnknown := 0
			clientHosts := ""
			serverHosts := ""
			for _, elemtLvl3 := range elemtLvl2.SonsLvl2 {
				nbrClients += len(elemtLvl3.Clients)
				nbrServers += len(elemtLvl3.Servers)
				for _, client := range elemtLvl3.Clients {
					clientHosts += client.Hostname + ":" + client.OperatingSystem + ":" + client.OperatingSystemVersion + ","
				}
				for _, server := range elemtLvl3.Servers {
					serverHosts += server.Hostname + ":" + server.OperatingSystem + ":" + server.OperatingSystemVersion + ","
				}
			}

			percClients := (100 * nbrClients) / (nbrClients + nbrServers)
			percServers := 100 - percClients
			mostPopular := ""
			percPopular := 0
			if percClients > percServers {
				mostPopular = "Client"
				percPopular = percClients
			} else {
				mostPopular = "Server"
				percPopular = percServers
			}
			percUnknown := 0
			f.SetCellValue("Sheet1", "A"+strconv.Itoa(index), ip)
			f.SetCellValue("Sheet1", "B"+strconv.Itoa(index), mask)
			f.SetCellValue("Sheet1", "C"+strconv.Itoa(index), nbrClients)
			f.SetCellValue("Sheet1", "D"+strconv.Itoa(index), percClients)
			f.SetCellValue("Sheet1", "E"+strconv.Itoa(index), nbrServers)
			f.SetCellValue("Sheet1", "F"+strconv.Itoa(index), percServers)
			f.SetCellValue("Sheet1", "G"+strconv.Itoa(index), nbrUnknown)
			f.SetCellValue("Sheet1", "H"+strconv.Itoa(index), percUnknown)
			f.SetCellValue("Sheet1", "I"+strconv.Itoa(index), mostPopular)
			f.SetCellValue("Sheet1", "J"+strconv.Itoa(index), percPopular)
			f.SetCellValue("Sheet1", "K"+strconv.Itoa(index), clientHosts)
			f.SetCellValue("Sheet1", "L"+strconv.Itoa(index), serverHosts)

			for _, elemtLvl3 := range elemtLvl2.SonsLvl2 {

				index++
				ip := elemtLvl2.IpLvl2
				mask := getMaskSize(elemtLvl2.IpLvl2)
				nbrClients := len(elemtLvl3.Clients)
				nbrServers := len(elemtLvl3.Servers)
				nbrUnknown := 0
				clientHosts := ""
				serverHosts := ""

				for _, client := range elemtLvl3.Clients {
					clientHosts += client.Hostname + ":" + client.OperatingSystem + ":" + client.OperatingSystemVersion + ","
				}
				for _, server := range elemtLvl3.Servers {
					serverHosts += server.Hostname + ":" + server.OperatingSystem + ":" + server.OperatingSystemVersion + ","
				}

				percClients := (100 * nbrClients) / (nbrClients + nbrServers)
				percServers := 100 - percClients
				mostPopular := ""
				percPopular := 0
				if percClients > percServers {
					mostPopular = "Client"
					percPopular = percClients
				} else {
					mostPopular = "Server"
					percPopular = percServers
				}
				percUnknown := 0
				f.SetCellValue("Sheet1", "A"+strconv.Itoa(index), ip)
				f.SetCellValue("Sheet1", "B"+strconv.Itoa(index), mask)
				f.SetCellValue("Sheet1", "C"+strconv.Itoa(index), nbrClients)
				f.SetCellValue("Sheet1", "D"+strconv.Itoa(index), percClients)
				f.SetCellValue("Sheet1", "E"+strconv.Itoa(index), nbrServers)
				f.SetCellValue("Sheet1", "F"+strconv.Itoa(index), percServers)
				f.SetCellValue("Sheet1", "G"+strconv.Itoa(index), nbrUnknown)
				f.SetCellValue("Sheet1", "H"+strconv.Itoa(index), percUnknown)
				f.SetCellValue("Sheet1", "I"+strconv.Itoa(index), mostPopular)
				f.SetCellValue("Sheet1", "J"+strconv.Itoa(index), percPopular)
				f.SetCellValue("Sheet1", "K"+strconv.Itoa(index), clientHosts)
				f.SetCellValue("Sheet1", "L"+strconv.Itoa(index), serverHosts)
			}
		}
	}

	if err := f.SaveAs(fileName); err != nil {
		println(err.Error())
	}

	CSVAdNetworkFileName = fileName
}

func displayLocalNetworkResult(Tree TreeIP) {

	CreateOutputolder()

	fileName := path.Join(outFolder, "Local_Network_"+time.Now().Format("2006.01.02-15.04.05")+".xlsx")

	fmt.Println("Priting Network results in ", fileName)
	f := excelize.NewFile()

	f.SetCellValue("Sheet1", "A1", "IP Range")
	f.SetCellValue("Sheet1", "B1", "Mask Size")
	f.SetCellValue("Sheet1", "C1", "#Clients")
	f.SetCellValue("Sheet1", "D1", "%Clients")
	f.SetCellValue("Sheet1", "E1", "#Servers")
	f.SetCellValue("Sheet1", "F1", "%Servers")
	f.SetCellValue("Sheet1", "G1", "#Unknown")
	f.SetCellValue("Sheet1", "H1", "%Unknown")
	f.SetCellValue("Sheet1", "I1", "Most Popular")
	f.SetCellValue("Sheet1", "J1", "%Most Popular")
	f.SetCellValue("Sheet1", "K1", "Client hosts")
	f.SetCellValue("Sheet1", "L1", "Server hosts")

	var index int = 1

	for _, elmntLvl1 := range Tree.Content {

		index++
		ip := elmntLvl1.IpLvl1
		mask := getMaskSize(elmntLvl1.IpLvl1)
		nbrClients := 0
		nbrServers := 0
		nbrUnknown := 0
		clientHosts := ""
		serverHosts := ""
		for _, elemtLvl2 := range elmntLvl1.SonsLvl1 {
			for _, elemtLvl3 := range elemtLvl2.SonsLvl2 {
				nbrUnknown += len(elemtLvl3.Clients)
			}
		}
		percClients := 0
		percServers := 0
		percUnknown := 0
		mostPopular := "Unknown"
		percPopular := 100

		f.SetCellValue("Sheet1", "A"+strconv.Itoa(index), ip)
		f.SetCellValue("Sheet1", "B"+strconv.Itoa(index), mask)
		f.SetCellValue("Sheet1", "C"+strconv.Itoa(index), nbrClients)
		f.SetCellValue("Sheet1", "D"+strconv.Itoa(index), percClients)
		f.SetCellValue("Sheet1", "E"+strconv.Itoa(index), nbrServers)
		f.SetCellValue("Sheet1", "F"+strconv.Itoa(index), percServers)
		f.SetCellValue("Sheet1", "G"+strconv.Itoa(index), nbrUnknown)
		f.SetCellValue("Sheet1", "H"+strconv.Itoa(index), percUnknown)
		f.SetCellValue("Sheet1", "I"+strconv.Itoa(index), mostPopular)
		f.SetCellValue("Sheet1", "J"+strconv.Itoa(index), percPopular)
		f.SetCellValue("Sheet1", "K"+strconv.Itoa(index), clientHosts)
		f.SetCellValue("Sheet1", "L"+strconv.Itoa(index), serverHosts)

		for _, elemtLvl2 := range elmntLvl1.SonsLvl1 {

			index++
			ip := elemtLvl2.IpLvl2
			mask := getMaskSize(elemtLvl2.IpLvl2)
			nbrClients := 0
			nbrServers := 0
			nbrUnknown := 0
			clientHosts := ""
			serverHosts := ""
			for _, elemtLvl3 := range elemtLvl2.SonsLvl2 {
				nbrUnknown += len(elemtLvl3.Clients)
			}

			percClients := 0
			percServers := 0
			percUnknown := 0

			mostPopular := "Unknown"
			percPopular := 100
			f.SetCellValue("Sheet1", "A"+strconv.Itoa(index), ip)
			f.SetCellValue("Sheet1", "B"+strconv.Itoa(index), mask)
			f.SetCellValue("Sheet1", "C"+strconv.Itoa(index), nbrClients)
			f.SetCellValue("Sheet1", "D"+strconv.Itoa(index), percClients)
			f.SetCellValue("Sheet1", "E"+strconv.Itoa(index), nbrServers)
			f.SetCellValue("Sheet1", "F"+strconv.Itoa(index), percServers)
			f.SetCellValue("Sheet1", "G"+strconv.Itoa(index), nbrUnknown)
			f.SetCellValue("Sheet1", "H"+strconv.Itoa(index), percUnknown)
			f.SetCellValue("Sheet1", "I"+strconv.Itoa(index), mostPopular)
			f.SetCellValue("Sheet1", "J"+strconv.Itoa(index), percPopular)
			f.SetCellValue("Sheet1", "K"+strconv.Itoa(index), clientHosts)
			f.SetCellValue("Sheet1", "L"+strconv.Itoa(index), serverHosts)

			for _, elemtLvl3 := range elemtLvl2.SonsLvl2 {

				index++
				ip := elemtLvl2.IpLvl2
				mask := getMaskSize(elemtLvl2.IpLvl2)
				nbrClients := 0
				nbrServers := 0
				nbrUnknown := len(elemtLvl3.Clients)
				clientHosts := ""
				serverHosts := ""

				percClients := 0
				percServers := 0
				percUnknown := 0
				mostPopular := "Unknown"
				percPopular := 100

				f.SetCellValue("Sheet1", "A"+strconv.Itoa(index), ip)
				f.SetCellValue("Sheet1", "B"+strconv.Itoa(index), mask)
				f.SetCellValue("Sheet1", "C"+strconv.Itoa(index), nbrClients)
				f.SetCellValue("Sheet1", "D"+strconv.Itoa(index), percClients)
				f.SetCellValue("Sheet1", "E"+strconv.Itoa(index), nbrServers)
				f.SetCellValue("Sheet1", "F"+strconv.Itoa(index), percServers)
				f.SetCellValue("Sheet1", "G"+strconv.Itoa(index), nbrUnknown)
				f.SetCellValue("Sheet1", "H"+strconv.Itoa(index), percUnknown)
				f.SetCellValue("Sheet1", "I"+strconv.Itoa(index), mostPopular)
				f.SetCellValue("Sheet1", "J"+strconv.Itoa(index), percPopular)
				f.SetCellValue("Sheet1", "K"+strconv.Itoa(index), clientHosts)
				f.SetCellValue("Sheet1", "L"+strconv.Itoa(index), serverHosts)
			}
		}
	}

	if err := f.SaveAs(fileName); err != nil {
		println(err.Error())
	}

	CSVLocalNetworkFileName = fileName
}

func CsvToHTML(csvfilename string) string {

	htmlFileName := strings.TrimSuffix(csvfilename, filepath.Ext(csvfilename)) + ".html"

	f, _ := os.Create(htmlFileName)

	defer f.Close()

	f.WriteString("<!DOCTYPE html>\n")
	f.WriteString("<html>\n")
	f.WriteString("<head>\n")
	f.WriteString("<style>\n")
	f.WriteString("table, th, td {		\n")
	f.WriteString("  border: 1px solid black;	\n")
	f.WriteString("  border-collapse: collapse;	\n")
	f.WriteString("}		\n")
	f.WriteString("th, td {		\n")
	f.WriteString("  padding: 5px;	\n")
	f.WriteString("  text-align: left;    	\n")
	f.WriteString("}\n")
	f.WriteString("</style>	\n")
	f.WriteString("</head>	\n")
	f.WriteString("\n")

	f.WriteString("<body>	\n")

	f.WriteString("\n")
	f.WriteString("<table style='width:100%'>	\n")
	f.WriteString("\n")
	f.WriteString("\n")

	csvFile, err := os.Open(csvfilename)
	if err != nil {
		fmt.Println(err)
	}

	defer csvFile.Close()

	csvLines, err := csv.NewReader(csvFile).ReadAll()
	if err != nil {
		fmt.Println(err)
	}
	for _, line := range csvLines {
		f.WriteString("<tr>\n")

		for _, column := range line {
			f.WriteString("<th>" + column + "</th>\n") // IP
		}

		f.WriteString("</tr>\n")
	}

	f.WriteString("</table>\n")
	f.WriteString("\n")
	f.WriteString("</body>\n")
	f.WriteString("</html>\n")

	f.Sync()

	return htmlFileName
}

func displayLocalAssetsResult(csvrows [][]string) {

	CreateOutputolder()

	fileName := path.Join(outFolder, "Local_Assets"+time.Now().Format("2006.01.02-15.04.05")+".xlsx")

	f := excelize.NewFile()

	fmt.Println("Priting Assets results in ", fileName)

	f.SetCellValue("Sheet1", "A1", "IP Address")
	f.SetCellValue("Sheet1", "B1", "TCP Open Ports")

	for index, row := range csvrows {
		ip := row[0]
		ports := row[1]

		f.SetCellValue("Sheet1", "A"+strconv.Itoa(index+2), ip)
		f.SetCellValue("Sheet1", "B"+strconv.Itoa(index+2), ports)

	}

	if err := f.SaveAs(fileName); err != nil {
		println(err.Error())
	}

	CSVLocalAssetsFileName = fileName
}

/*
func ScanNmapTCPPort(ipaddr string, tcpPorts []int, slicescanresult *[]ScanResult) error {

	ports := append(tcpPorts)

	sPorts := strconv.Itoa(ports[0])

	for i := 1; i < len(ports); i++ {
		sPorts = sPorts + "," + strconv.Itoa(ports[i])
	}

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Minute)
	defer cancel()

	scanner, err := nmap.NewScanner(
		nmap.WithTargets(ipaddr),
		nmap.WithPorts(sPorts),
		nmap.WithContext(ctx),
	)
	if err != nil {
		return err
	}

	result, _, err := scanner.Run()

	if err != nil {
		return err
	}

	for _, host := range result.Hosts {
		for _, port := range host.Ports {
			fmt.Printf("\tHost %s Port %d/%s %s %s\n", host.Addresses[0].String(), port.ID, port.Protocol, port.State, port.Service.Name)
		}
	}

	return err
}

func ScanNmapUDPPort(ipaddr string, ports []int) bool {

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Minute)
	defer cancel()

	sUDPPorts := strconv.Itoa(ports[0])

	for i := 1; i < len(ports); i++ {
		sUDPPorts = sUDPPorts + "," + strconv.Itoa(ports[i])
	}

	scanner, err := nmap.NewScanner(
		nmap.WithTargets(ipaddr),
		nmap.WithPorts(sUDPPorts),
		nmap.WithContext(ctx),
		nmap.WithUDPScan(),
	)
	if err != nil {
		return false
	}

	result, _, err := scanner.Run()

	if err != nil {
		return false
	}

	for _, host := range result.Hosts {
		for _, port := range host.Ports {
			fmt.Printf("\tHost %s Port %d/%s %s %s\n", host.Addresses[0].String(), port.ID, port.Protocol, port.State, port.Service.Name)
		}
	}

	//State := strings.ToLower(result.Hosts[0].Ports[0].State.String())

	return false

}
*/
var retries int = 0

func GetOnlineHosts(ipList []string) []string {

	var onlineHosts []string

	result := make(chan PingResult, len(ipList))

	var index int = 0
	for _, ip := range ipList {
		if index < 50 {
			index++
			time.Sleep(15 * time.Millisecond)
		} else {
			index = 0
			time.Sleep(30 * time.Millisecond)
		}

		go isHostNameReachable(ip, result, retries)
	}

	for i := range ipList {
		status := <-result

		if false {
			fmt.Println("Result #", i, " ", status.IP, " is ", status.Status)
		}

		if status.Status == "ONLINE" {
			onlineHosts = append(onlineHosts, status.IP)
		}
	}

	return onlineHosts
}

/*
func nmapGetOnlineHosts(ipList []string) ([]string, error) {

	scanner, err := nmap.NewScanner(
		nmap.WithTargets(ipList...),
		nmap.WithPingScan(),
	)
	if err != nil {
		return []string{}, err
	}

	result, warnings, err := scanner.Run()

	if err != nil {
		fmt.Println(warnings)
		return []string{}, err
	}

	var ipOnline []string
	for _, host := range result.Hosts {
		ipOnline = append(ipOnline, host.Addresses[0].String())
	}

	fmt.Println(ipOnline)

	return ipOnline, err
}

*/

type PortIP struct {
	IP   string
	Port int
}

func ScanPort(ip string, port int, timeout time.Duration) bool {
	target := fmt.Sprintf("%s:%d", ip, port)
	conn, err := net.DialTimeout("tcp", target, timeout)

	if err != nil {
		if strings.Contains(err.Error(), "too many open files") {
			fmt.Println("Error scanning", target, " too many files, Retrying after 5 seconds")
			time.Sleep(timeout)
			ScanPort(ip, port, timeout)
		} else {
			return false
		}
		return false
	}

	conn.Close()

	return true
}

func worker(ports chan PortIP, results chan ScanResult) {

	for portip := range ports {
		ip := portip.IP
		port := portip.Port

		bOpen := ScanPort(ip, port, 5*time.Second)
		if bOpen {
			fmt.Println("Checking ", ip, ":", port, "==> Open")
			results <- ScanResult{IP: ip, Port: port, State: "open", Protocol: "tcp"}
		} else {
			fmt.Println("Checking ", ip, ":", port, "==> Closed")
			results <- ScanResult{IP: ip, Port: port, State: "closed", Protocol: "tcp"}
		}
	}
}

func deleteEmpty(s []string) []string {
	var r []string
	for _, str := range s {
		if str != "" {
			r = append(r, str)
		}
	}
	return r
}

func removeWhitesString(str string) string {
	str = strings.ReplaceAll(str, " ", "")
	str = strings.ReplaceAll(str, "\n", "")
	str = strings.ReplaceAll(str, "\t", "")
	str = strings.ReplaceAll(str, "\r", "")

	return str
}

func getOperatingSystem(ADCsvResults [][]string) []string {
	var OpeartingSystems []string
	for _, row := range ADCsvResults {
		OS := row[5]
		OpeartingSystems = append(OpeartingSystems, OS)
	}
	OpeartingSystems = unique(OpeartingSystems)
	return OpeartingSystems
}

func getNumberOfAccessibleHosts(ADCsvResults [][]string) (int, int) {
	total := len(ADCsvResults)
	var accessible int
	for _, row := range ADCsvResults {
		tcpOpentPorts := row[len(row)-1]
		if len(tcpOpentPorts) > 0 {
			accessible++
		}
	}
	return accessible, total
}

func getNumberOfAccessibleHostsByType(ADCsvResults [][]string, Type string) (int, int) {
	var total int
	var accessible int
	for _, row := range ADCsvResults {
		hostType := strings.ToLower(row[2])
		Type = strings.ToLower(Type)
		if hostType != Type {
			continue
		}
		total++
		tcpOpentPorts := row[len(row)-1]
		if len(tcpOpentPorts) > 0 {
			accessible++
		}
	}
	return accessible, total
}

func getTcpOpenPorts(ADCsvResults [][]string) []string {
	var TCPports []string
	for _, row := range ADCsvResults {
		tcpOpentPortsRow := row[len(row)-1]
		TCPports = append(TCPports, strings.Split(tcpOpentPortsRow, "|")...)
	}

	TCPports = deleteEmpty(TCPports)
	fmt.Println(TCPPorts)
	return TCPports
}

func unique(stringSlice []string) []string {
	keys := make(map[string]bool)
	list := []string{}
	for _, entry := range stringSlice {
		if _, value := keys[entry]; !value {
			keys[entry] = true
			list = append(list, entry)
		}
	}
	return list
}

func getNumberOfHostsWithOpenPortByType(ADCsvResults [][]string, openport string, Type string) (int, int) {
	var nbrOfHostsOfType int
	var total int
	for _, row := range ADCsvResults {
		hostType := strings.ToLower(row[2])
		Type = strings.ToLower(Type)
		if hostType != Type {
			continue
		}
		total++
		tcpOpentPorts := row[len(row)-1]
		if strings.Contains(tcpOpentPorts, openport) {
			nbrOfHostsOfType++
		}
	}
	return nbrOfHostsOfType, total
}

func dupCount(list []string) map[string]int {
	duplicateFrequency := make(map[string]int)
	for _, item := range list {
		// check if the item/element exist in the duplicate_frequency map
		_, exist := duplicateFrequency[item]
		if exist {
			duplicateFrequency[item] += 1 // increase counter by 1 if already in the map
		} else {
			duplicateFrequency[item] = 1 // else start counting from 1
		}
	}
	return duplicateFrequency
}

var scanDurationStr string = ""
var scanDateTime string = ""
var nbrAssets string = ""
var TCPOpenPortsSlice []string

type DataJson struct {
	Title   string `json:"Title"`
	Desc    string `json:"desc"`
	Content string `json:"content"`
}

func GetScanDurationStr(w http.ResponseWriter, r *http.Request) {

	enableCors(&w)

	duration := DataJson{
		Title:   "Duration",
		Desc:    "Duration of the last scan done",
		Content: scanDurationStr,
	}

	fmt.Println("Returning duration of the scan", scanDurationStr)
	json.NewEncoder(w).Encode(duration)
}

func GetScanDateTimeStr(w http.ResponseWriter, r *http.Request) {

	enableCors(&w)

	datetime := DataJson{
		Title:   "DateTime",
		Desc:    "Date and Time of the last scan done",
		Content: scanDateTime,
	}

	fmt.Println("Returning Date and Time of the last scan", scanDateTime)
	json.NewEncoder(w).Encode(datetime)
}

func GetUserName(w http.ResponseWriter, r *http.Request) {

	enableCors(&w)

	username, _ := executePowerShell("$env:UserName")
	username = removeWhitesString(username)

	datetime := DataJson{
		Title:   "User",
		Desc:    "Current username",
		Content: username,
	}

	fmt.Println("Returning username", username)
	json.NewEncoder(w).Encode(datetime)
}

func GetFQDN(w http.ResponseWriter, r *http.Request) {

	enableCors(&w)

	fqdn, _ := executePowerShell("[System.Net.Dns]::GetHostByName($env:computerName).HostName")
	fqdn = removeWhitesString(fqdn)

	datetime := DataJson{
		Title:   "FQDN",
		Desc:    "Current FQDN",
		Content: fqdn,
	}

	fmt.Println("Returning FQDN", fqdn)
	json.NewEncoder(w).Encode(datetime)
}

func GetIP(w http.ResponseWriter, r *http.Request) {

	enableCors(&w)

	// Get IP Address
	ipAddr, _ := executePowerShell("[System.Net.Dns]::GetHostByName($env:computerName).AddressList.IPAddressToString")
	ipAddr = removeWhitesString(ipAddr)

	datetime := DataJson{
		Title:   "IP",
		Desc:    "Current ip address",
		Content: ipAddr,
	}

	fmt.Println("Returning ip address", ipAddr)
	json.NewEncoder(w).Encode(datetime)
}

func GetAssetsNbr(w http.ResponseWriter, r *http.Request) {

	enableCors(&w)

	datetime := DataJson{
		Title:   "Assets",
		Desc:    "Current ip address",
		Content: nbrAssets,
	}

	fmt.Println("Returning number of accessible assets", nbrAssets)
	json.NewEncoder(w).Encode(datetime)
}

type kv struct {
	Key   string
	Value int
}

func OrderMayByValue(MapToOrder map[string]int) []kv {

	var ss []kv
	for k, v := range MapToOrder {
		ss = append(ss, kv{k, v})
	}

	sort.Slice(ss, func(i, j int) bool {
		return ss[i].Value > ss[j].Value
	})

	return ss
}

var mostPopularPorts []kv
var TCPMap map[string]int

func GetOpenPorts() {

	if len(ADTCPOpenPorts) != 0 {
		TCPOpenPortsSlice = ADTCPOpenPorts
	} else {
		TCPOpenPortsSlice = LocalTCPOpenPorts
	}

	TCPMap = dupCount(TCPOpenPortsSlice)

	fmt.Println("All open ports", TCPMap)

	mostPopularPorts = OrderMayByValue(TCPMap)

	fmt.Println("Most Popular ports order", mostPopularPorts)
}

func GetPopularPortsByType(Type string, Port string) int {
	var nbrOfHostsOfType int
	var total int
	for _, row := range ADCsvResults {
		hostType := strings.ToLower(row[2])
		Type = strings.ToLower(Type)
		if hostType != Type {
			continue
		}
		total++
		tcpOpentPorts := row[len(row)-1]
		if strings.Contains(tcpOpentPorts, Port) {
			nbrOfHostsOfType++
		}
	}
	return nbrOfHostsOfType
}

func GetPopularPorts(w http.ResponseWriter, r *http.Request) {

	GetOpenPorts()

	enableCors(&w)

	popularPort1 := mostPopularPorts[0].Key
	popularPort2 := mostPopularPorts[1].Key
	popularPort3 := mostPopularPorts[2].Key

	popularPort1ServerOcc := GetPopularPortsByType("server", popularPort1) / TCPMap[popularPort1] * 100
	popularPort2ServerOcc := GetPopularPortsByType("server", popularPort2) / TCPMap[popularPort2] * 100
	popularPort3ServerOcc := GetPopularPortsByType("server", popularPort3) / TCPMap[popularPort3] * 100

	popularPort1ClientOcc := GetPopularPortsByType("client", popularPort1) / TCPMap[popularPort1] * 100
	popularPort2ClientOcc := GetPopularPortsByType("client", popularPort2) / TCPMap[popularPort2] * 100
	popularPort3ClientOcc := GetPopularPortsByType("client", popularPort3) / TCPMap[popularPort3] * 100

	mostPopularPortsNames := []string{popularPort1, popularPort2, popularPort3}
	mostPopularPortsServer := []int{popularPort1ServerOcc, popularPort2ServerOcc, popularPort3ServerOcc}
	mostPopularPortsClient := []int{popularPort1ClientOcc, popularPort2ClientOcc, popularPort3ClientOcc}

	type DataPortCount struct {
		PopularPorts          []string `json:"popular_ports"`
		PopularPortsServerOcc []int    `json:"server_occ"`
		PopularPortsClientOcc []int    `json:"client_occ"`
	}

	Data := DataPortCount{
		PopularPorts:          mostPopularPortsNames,
		PopularPortsServerOcc: mostPopularPortsServer,
		PopularPortsClientOcc: mostPopularPortsClient,
	}

	fmt.Println("Returning most open popular ports ordered by value", Data)
	json.NewEncoder(w).Encode(Data)
}

func GetAllOperatingSystems(w http.ResponseWriter, r *http.Request) {

	enableCors(&w)

	type DataPortCount struct {
		OS []string `json:"os"`
	}

	osSlice := getOperatingSystem(ADCsvResults)

	datetime := DataPortCount{
		OS: osSlice,
	}

	fmt.Println("Returning Discovered Operating Systems ", osSlice)
	json.NewEncoder(w).Encode(datetime)

}

func index(slice []string, item string) int {
	return -1
}

func getPortServiceByPortNumber(port string) string {

	for index, _ := range TCPPorts {
		if strconv.Itoa(TCPPorts[index]) == port {
			return ServicePorts[index]
		}
	}

	return " "
}

func GetAllOpenPorts(w http.ResponseWriter, r *http.Request) {

	enableCors(&w)

	type DataPortCount struct {
		OpenPorts []string `json:"open_ports"`
	}

	var openPorts []string

	if len(ADTCPOpenPorts) != 0 {
		openPorts = ADTCPOpenPorts
	} else {
		openPorts = LocalTCPOpenPorts
	}

	openPorts = unique(openPorts)

	var openPortsService []string
	for _, port := range openPorts {
		openPortsService = append(openPortsService, port+"/"+getPortServiceByPortNumber(port))
	}

	datetime := DataPortCount{
		OpenPorts: openPortsService,
	}

	fmt.Println("Returning unique open  ports ", openPortsService)
	json.NewEncoder(w).Encode(datetime)
}

func GetAccPercentAD(w http.ResponseWriter, r *http.Request) {

	enableCors(&w)

	type DataPortCount struct {
		Accessible int `json:"acc"`
		Total      int `json:"total"`
	}

	datetime := DataPortCount{
		Accessible: nbrAccessibleHostsAD,
		Total:      totalHostsAD,
	}

	if totalHostsAD != 0 {
		fmt.Println("Returning % Accessible assets / total", nbrAccessibleHostsAD/totalHostsAD*100)
	}
	json.NewEncoder(w).Encode(datetime)
}

func GetAccPercentLoc(w http.ResponseWriter, r *http.Request) {
	enableCors(&w)

	type DataPortCount struct {
		Accessible int `json:"acc"`
		Total      int `json:"total"`
	}

	datetime := DataPortCount{
		Accessible: nbrAccessibleHostsLoc,
		Total:      totalHostsLoc,
	}

	if totalHostsLoc != 0 {
		fmt.Println("Returning % Accessible assets / total", nbrAccessibleHostsLoc/totalHostsLoc*100)
	}
	json.NewEncoder(w).Encode(datetime)
}

func GetPercByType(w http.ResponseWriter, r *http.Request) {
	enableCors(&w)

	type DataPortCount struct {
		Servers int `json:"servers"`
		Clients int `json:"clients"`
	}

	var datetime DataPortCount
	if machineIsDomainConnected() {
		datetime = DataPortCount{
			Servers: nbrServerWithOpenPort * 100 / totalHostsAD,
			Clients: nbrClientWithOpenPort * 100 / totalHostsAD,
		}
	} else {
		datetime = DataPortCount{
			Servers: 0,
			Clients: 0,
		}
	}

	fmt.Println("**********************************************************")
	fmt.Println("Servers ", nbrServerWithOpenPort, " Total ", totalHostsAD)
	fmt.Println("Clients ", nbrClientWithOpenPort, " Total ", totalHostsAD)
	fmt.Println(datetime)
	fmt.Println("**********************************************************")

	if totalHostsAD != 0 {
		fmt.Println("Returning % Accessible assets / total", nbrAccessibleHostsAD*100/totalHostsAD)
	}

	json.NewEncoder(w).Encode(datetime)

}

func GetIPPorts(w http.ResponseWriter, r *http.Request) {

	enableCors(&w)

	var ips []string
	var ports []int

	for _, row := range LocalCsvResults {
		ip := row[0]
		portsRow := strings.ReplaceAll(row[1], "|", " ")

		Nbrports := WordCount(portsRow)

		fmt.Println(row[0], "====> ", Nbrports)

		ips = append(ips, ip)
		ports = append(ports, Nbrports)
	}

	type DataPortCount struct {
		IP    []string `json:"ip"`
		Ports []int    `json:"ports"`
	}

	datetime := DataPortCount{
		IP:    ips,
		Ports: ports,
	}

	fmt.Println("Returning Slice number of ports opened / ip", ips, ports)
	json.NewEncoder(w).Encode(datetime)
}

func PrepareIPSummary() {

	if machineIsDomainConnected() {

		for _, row := range ADCsvResults {
			_FQDN := row[0]
			_Hostname := row[1]
			_Type := row[2]
			_Ip := row[3]
			s := strings.Split(_Ip, ".")
			var _IP_LEV1 string
			var _IP_LEV2 string
			var _IP_LEV3 string
			if len(s) > 2 {
				_IP_LEV1 = s[0] + ".*.*.*"
				_IP_LEV2 = s[0] + "." + s[1] + ".*.*"
				_IP_LEV3 = s[0] + "." + s[1] + "." + s[2] + ".*"
			} else {
				_Ip = strings.ReplaceAll(_Ip, "::", ":")
				s := strings.Split(_Ip, ":")
				_IP_LEV1 = s[0] + ":*:*:*"
				_IP_LEV2 = s[0] + ":" + s[1] + ":*:*"
				_IP_LEV3 = s[0] + ":" + s[1] + ":" + s[2] + ":*"
			}

			IP_Level1_array = append(IP_Level1_array, _IP_LEV1)
			IP_Level2_array = append(IP_Level2_array, _IP_LEV2)
			IP_Level3_array = append(IP_Level3_array, _IP_LEV3)

			IP_Level1_array = unique(IP_Level1_array)
			IP_Level2_array = unique(IP_Level2_array)
			IP_Level3_array = unique(IP_Level3_array)

			_ComputerName := row[4]
			_OperatingSystem := row[5]
			_OperatingSystemVersion := row[6]
			_DistinguishedName := row[7]
			_TCPPorts := row[8]
			_Time := scanDateTime

			_TCPPorts = strings.ReplaceAll(_TCPPorts, "|", " ")

			ipTcpPort := DataIPOpenPort{
				FQDN:                   _FQDN,
				Hostname:               _Hostname,
				Type:                   _Type,
				Ip:                     _Ip,
				ComputerName:           _ComputerName,
				OperatingSystem:        _OperatingSystem,
				OperatingSystemVersion: _OperatingSystemVersion,
				DistinguishedName:      _DistinguishedName,
				TCPPorts:               _TCPPorts,
				Time:                   _Time,
			}

			IPData = append(IPData, ipTcpPort)
		}

		// Populate level1
		for _, iplev1 := range IP_Level1_array {
			Item1 := ItemLvl1{IpLvl1: iplev1}
			treeIP.Content = append(treeIP.Content, Item1)
		}

		// Populate level2
		for _, iplev2 := range IP_Level2_array {
			Item2 := ItemLvl2{IpLvl2: iplev2}

			for index, itemTree := range treeIP.Content {
				sLv1 := strings.Split(itemTree.IpLvl1, ".")
				if len(sLv1) < 2 {
					sLv1 = strings.Split(itemTree.IpLvl1, ":")
				}

				sLv2 := strings.Split(Item2.IpLvl2, ".")
				if len(sLv2) < 2 {
					sLv2 = strings.Split(Item2.IpLvl2, ":")
				}

				if sLv1[0] == sLv2[0] {
					treeIP.Content[index].SonsLvl1 = append(treeIP.Content[index].SonsLvl1, Item2)
				}
			}
		}

		// Populate level3
		for _, iplev3 := range IP_Level3_array {
			Item3 := ItemLvl3{IpLvl3: iplev3}

			for index1, itemTree := range treeIP.Content {
				for index2, son := range itemTree.SonsLvl1 {
					sLv2 := strings.Split(son.IpLvl2, ".")
					if len(sLv2) < 2 {
						sLv2 = strings.Split(son.IpLvl2, ":")
					}

					sLv3 := strings.Split(Item3.IpLvl3, ".")
					if len(sLv3) < 2 {
						sLv3 = strings.Split(Item3.IpLvl3, ":")
					}

					if (sLv2[0] == sLv3[0]) && (sLv2[1] == sLv3[1]) {
						treeIP.Content[index1].SonsLvl1[index2].SonsLvl2 = append(treeIP.Content[index1].SonsLvl1[index2].SonsLvl2, Item3)
					}
				}
			}
		}

		for _, ipData := range IPData {
			for index1, itemTree := range treeIP.Content {
				for index2, son := range itemTree.SonsLvl1 {
					for index3, grandSon := range son.SonsLvl2 {
						sLv3 := strings.Split(grandSon.IpLvl3, ".")
						if len(sLv3) < 2 {
							sLv3 = strings.Split(grandSon.IpLvl3, ":")
						}

						sLv4 := strings.Split(ipData.Ip, ".")
						if len(sLv4) < 2 {
							sLv4 = strings.Split(ipData.Ip, ":")
						}

						if (sLv3[0] == sLv4[0]) && (sLv3[1] == sLv4[1]) && (sLv3[2] == sLv4[2]) {
							if ipData.Type == "Client" {
								ipv6 := strings.Split(ipData.Ip, ":")
								if len(ipv6) > 2 { // This is an ipv6 address, fix it!
									ipData.Ip = ipv6[0] + "::" + ipv6[1] + ":" + ipv6[2] + ":" + ipv6[3]
								}
								treeIP.Content[index1].SonsLvl1[index2].SonsLvl2[index3].Clients = append(treeIP.Content[index1].SonsLvl1[index2].SonsLvl2[index3].Clients, ipData)
							} else if ipData.Type == "Server" {
								ipv6 := strings.Split(ipData.Ip, ":")
								if len(ipv6) > 2 { // This is an ipv6 address, fix it!
									ipData.Ip = ipv6[0] + "::" + ipv6[1] + ":" + ipv6[2] + ":" + ipv6[3]
								}
								treeIP.Content[index1].SonsLvl1[index2].SonsLvl2[index3].Servers = append(treeIP.Content[index1].SonsLvl1[index2].SonsLvl2[index3].Servers, ipData)
							}
						}
					}
				}
			}
		}
	} else {
		for _, row := range LocalCsvResults {
			_Ip := row[0]
			_TCPPorts := row[1]

			s := strings.Split(_Ip, ".")
			var _IP_LEV1 string
			var _IP_LEV2 string
			var _IP_LEV3 string
			if len(s) > 2 {
				_IP_LEV1 = s[0] + ".*.*.*"
				_IP_LEV2 = s[0] + "." + s[1] + ".*.*"
				_IP_LEV3 = s[0] + "." + s[1] + "." + s[2] + ".*"
			} else {
				_Ip = strings.ReplaceAll(_Ip, "::", ":")
				s := strings.Split(_Ip, ":")
				_IP_LEV1 = s[0] + ":*:*:*"
				_IP_LEV2 = s[0] + ":" + s[1] + ":*:*"
				_IP_LEV3 = s[0] + ":" + s[1] + ":" + s[2] + ":*"
			}

			IP_Level1_array = append(IP_Level1_array, _IP_LEV1)
			IP_Level2_array = append(IP_Level2_array, _IP_LEV2)
			IP_Level3_array = append(IP_Level3_array, _IP_LEV3)

			IP_Level1_array = unique(IP_Level1_array)
			IP_Level2_array = unique(IP_Level2_array)
			IP_Level3_array = unique(IP_Level3_array)

			_Time := scanDateTime

			_TCPPorts = strings.ReplaceAll(_TCPPorts, "|", " ")

			ipTcpPort := DataIPOpenPort{
				FQDN:                   "N/A",
				Hostname:               "N/A",
				Type:                   "N/A",
				Ip:                     _Ip,
				ComputerName:           "N/A",
				OperatingSystem:        "N/A",
				OperatingSystemVersion: "N/A",
				DistinguishedName:      "N/A",
				TCPPorts:               _TCPPorts,
				Time:                   _Time,
			}

			IPData = append(IPData, ipTcpPort)
		}

		// Populate level1
		for _, iplev1 := range IP_Level1_array {
			Item1 := ItemLvl1{IpLvl1: iplev1}
			treeIP.Content = append(treeIP.Content, Item1)
		}

		// Populate level2
		for _, iplev2 := range IP_Level2_array {
			Item2 := ItemLvl2{IpLvl2: iplev2}

			for index, itemTree := range treeIP.Content {
				sLv1 := strings.Split(itemTree.IpLvl1, ".")
				if len(sLv1) < 2 {
					sLv1 = strings.Split(itemTree.IpLvl1, ":")
				}

				sLv2 := strings.Split(Item2.IpLvl2, ".")
				if len(sLv2) < 2 {
					sLv2 = strings.Split(Item2.IpLvl2, ":")
				}

				if sLv1[0] == sLv2[0] {
					treeIP.Content[index].SonsLvl1 = append(treeIP.Content[index].SonsLvl1, Item2)
				}
			}
		}

		// Populate level3
		for _, iplev3 := range IP_Level3_array {
			Item3 := ItemLvl3{IpLvl3: iplev3}

			for index1, itemTree := range treeIP.Content {
				for index2, son := range itemTree.SonsLvl1 {
					sLv2 := strings.Split(son.IpLvl2, ".")
					if len(sLv2) < 2 {
						sLv2 = strings.Split(son.IpLvl2, ":")
					}

					sLv3 := strings.Split(Item3.IpLvl3, ".")
					if len(sLv3) < 2 {
						sLv3 = strings.Split(Item3.IpLvl3, ":")
					}

					if (sLv2[0] == sLv3[0]) && (sLv2[1] == sLv3[1]) {
						treeIP.Content[index1].SonsLvl1[index2].SonsLvl2 = append(treeIP.Content[index1].SonsLvl1[index2].SonsLvl2, Item3)
					}
				}
			}
		}

		for _, ipData := range IPData {
			for index1, itemTree := range treeIP.Content {
				for index2, son := range itemTree.SonsLvl1 {
					for index3, grandSon := range son.SonsLvl2 {
						sLv3 := strings.Split(grandSon.IpLvl3, ".")
						if len(sLv3) < 2 {
							sLv3 = strings.Split(grandSon.IpLvl3, ":")
						}

						sLv4 := strings.Split(ipData.Ip, ".")
						if len(sLv4) < 2 {
							sLv4 = strings.Split(ipData.Ip, ":")
						}

						if (sLv3[0] == sLv4[0]) && (sLv3[1] == sLv4[1]) && (sLv3[2] == sLv4[2]) {
							ipv6 := strings.Split(ipData.Ip, ":")
							if len(ipv6) > 2 { // This is an ipv6 address, fix it!
								ipData.Ip = ipv6[0] + "::" + ipv6[1] + ":" + ipv6[2] + ":" + ipv6[3]
							}
							treeIP.Content[index1].SonsLvl1[index2].SonsLvl2[index3].Clients = append(treeIP.Content[index1].SonsLvl1[index2].SonsLvl2[index3].Clients, ipData)
						}
					}
				}
			}
		}
	}
}

func GetIPSummary(w http.ResponseWriter, r *http.Request) {

	enableCors(&w)

	jsData, _ := json.Marshal(treeIP)
	fmt.Println("Returning IP summary of the scan", string(jsData))
	json.NewEncoder(w).Encode(treeIP)
}

func PrepareOSSummary() {

	if machineIsDomainConnected() {
		// Get Slice of Operating Systems
		var osarray []string
		for _, row := range ADCsvResults {
			_OperatingSystem := row[5]
			osarray = append(osarray, _OperatingSystem)
		}

		osarray = unique(osarray)

		for _, os := range osarray {
			var osIpData []DataIPOpenPort
			for _, row := range IPData {
				if os == row.OperatingSystem {
					osIpData = append(osIpData, row)
				}
			}

			OsElmnt := OsLvl1{
				OsName:   os,
				SonsLvl1: osIpData,
			}
			treeOS.Content = append(treeOS.Content, OsElmnt)
		}
	}
}

func GetADOSSummary(w http.ResponseWriter, r *http.Request) {

	enableCors(&w)

	jsData, _ := json.Marshal(treeOS)
	fmt.Println("Returning OS summary of the scan", string(jsData))
	json.NewEncoder(w).Encode(treeOS)
}

func PreparePortsSummary() {

	if machineIsDomainConnected() {
		// Get Slice of Operating Systems
		openPorts := unique(ADTCPOpenPorts)

		for _, port := range openPorts {
			var _Clients []DataIPOpenPort
			var _Servers []DataIPOpenPort

			for _, row := range IPData {
				if strings.Contains(row.TCPPorts, port) {
					if row.Type == "Client" {
						_Clients = append(_Clients, row)
					} else if row.Type == "Server" {
						_Servers = append(_Servers, row)
					}
				}
			}

			PortElmnt := PortsLvl1{
				Port:    port,
				Clients: _Clients,
				Servers: _Servers,
			}
			treePorts.Content = append(treePorts.Content, PortElmnt)
		}
	} else {
		openPorts := unique(LocalTCPOpenPorts)

		for _, port := range openPorts {
			var _Clients []DataIPOpenPort

			for _, row := range IPData {
				if strings.Contains(row.TCPPorts, port) {
					_Clients = append(_Clients, row)
				}
			}

			PortElmnt := PortsLvl1{
				Port:    port,
				Clients: _Clients,
			}
			treePorts.Content = append(treePorts.Content, PortElmnt)
		}
	}
}

func GetADPortsSummary(w http.ResponseWriter, r *http.Request) {

	enableCors(&w)

	jsData, _ := json.Marshal(treePorts)
	fmt.Println("Returning Ports summary of the scan", string(jsData))
	json.NewEncoder(w).Encode(treePorts)
}

func GetLocalPortsSummary(w http.ResponseWriter, r *http.Request) {

	enableCors(&w)

	jsData, _ := json.Marshal(treePorts)
	fmt.Println("Returning Ports summary of the scan", string(jsData))
	json.NewEncoder(w).Encode(treePorts)
}

func OpenAssetsDetails(w http.ResponseWriter, r *http.Request) {
	enableCors(&w)

	if len(CSVAdAssetsFileName) > 0 {
		openbrowser(CSVAdAssetsFileName)
	} else if len(CSVLocalAssetsFileName) > 0 {
		openbrowser(CSVLocalAssetsFileName)
	}

}

func OpenNetworkDetails(w http.ResponseWriter, r *http.Request) {
	enableCors(&w)

	if len(CSVAdAssetsFileName) > 0 {
		openbrowser(CSVAdNetworkFileName)
	} else if len(CSVLocalNetworkFileName) > 0 {
		openbrowser(CSVLocalNetworkFileName)
	}
}

func handleRequests() {

	http.HandleFunc("/getDuration", GetScanDurationStr)
	http.HandleFunc("/getDateTime", GetScanDateTimeStr)
	http.HandleFunc("/getUserName", GetUserName)
	http.HandleFunc("/getFqdn", GetFQDN)
	http.HandleFunc("/getIP", GetIP)
	http.HandleFunc("/getAssetsNbr", GetAssetsNbr)
	http.HandleFunc("/getIPPorts", GetIPPorts)
	http.HandleFunc("/getAccessiblePercentageAD", GetAccPercentAD)
	http.HandleFunc("/getAccessiblePercentageLoc", GetAccPercentLoc)
	http.HandleFunc("/getPercByType", GetPercByType)
	http.HandleFunc("/getPopularPortsByType", GetPopularPorts)
	http.HandleFunc("/getOperatingSystems", GetAllOperatingSystems)
	http.HandleFunc("/getAllOpenPorts", GetAllOpenPorts)
	http.HandleFunc("/getLocalPortsSummary", GetLocalPortsSummary)
	http.HandleFunc("/getIPSummary", GetIPSummary)
	http.HandleFunc("/getADOSSummary", GetADOSSummary)
	http.HandleFunc("/getADPortsSummary", GetADPortsSummary)
	http.HandleFunc("/openNetworkDetails", OpenNetworkDetails)
	http.HandleFunc("/openAssetsDetails", OpenAssetsDetails)

	log.Fatal(http.ListenAndServe(":8081", nil))
}

func enableCors(w *http.ResponseWriter) {
	(*w).Header().Set("Access-Control-Allow-Origin", "*")
}

func CreateOutputolder() error {

	outFolder = path.Join(GetDocumentsFolderPath(), "GoScanner Results")

	if _, err := os.Stat(outFolder); os.IsNotExist(err) {
		return os.Mkdir(outFolder, os.ModeDir|0755)
	}

	return nil
}

func main() {

	var wg sync.WaitGroup

	go func() {
		wg.Add(1)
		handleRequests()
	}()

	timeStartScan = time.Now()

	var computerList string

	fmt.Println("****************************************************************************")
	fmt.Println("Start the Scan NOW")

	CreateOutputolder()

	if machineIsDomainConnected() {

		domain := discoverDomain()

		if debug {
			fmt.Println("Domain Name : ", domain)
		}

		computerList = discoverComputers()

		fmt.Println(computerList)

		var dat map[string]map[string]interface{}

		if err := json.Unmarshal([]byte(computerList), &dat); err != nil {
			panic(err)
		}

		devices := dat["devices"]

		portsips := make(chan PortIP, len(TCPPorts)*len(devices))
		// this channel will receive results of scanning
		results := make(chan ScanResult)
		// create a slice to store the results so that they can be sorted later.
		var openports []ScanResult

		// create a pool of workers
		for i := 0; i < cap(portsips); i++ {
			go worker(portsips, results)
		}

		// send ports to be scanned
		go func() {
			for device, _ := range devices {
				device = strings.ReplaceAll(device, "\r", "")
				for _, port := range TCPPorts {
					portsips <- PortIP{Port: port, IP: device}
				}
			}
		}()

		for i := 0; i < len(devices)*len(TCPPorts); i++ {
			result := <-results
			if result.State == "open" {
				openports = append(openports, result)
			}
		}

		// After all the work has been completed, close the channels
		close(portsips)
		close(results)

		for device, _ := range devices {

			deviceInfo := getComputerInfofromIP(computerList, device)

			var CsvTCPOpenPorts string
			for _, portip := range openports {
				if portip.IP == device {
					if len(CsvTCPOpenPorts) == 0 {
						CsvTCPOpenPorts = strconv.Itoa(portip.Port)
					} else {
						CsvTCPOpenPorts = CsvTCPOpenPorts + "|" + strconv.Itoa(portip.Port)
					}
				}
			}

			CsvRecord := deviceInfo
			CsvRecord = append(CsvRecord, CsvTCPOpenPorts)
			ADCsvResults = append(ADCsvResults, CsvRecord)
		}
	}

	ipList := localSubnet()

	sort.Strings(ipList)

	fmt.Println("Removing Offline IPs from ", len(ipList), "hosts found on the network")

	onlineIPs := GetOnlineHosts(ipList)

	realIPs := make([]net.IP, 0, len(onlineIPs))

	for _, ip := range onlineIPs {
		realIPs = append(realIPs, net.ParseIP(ip))
	}

	sort.Slice(realIPs, func(i, j int) bool {
		return bytes.Compare(realIPs[i], realIPs[j]) < 0
	})

	for i, ip := range realIPs {
		onlineIPs[i] = ip.String()
	}

	fmt.Println(onlineIPs)

	fmt.Println("We discovered ", len(onlineIPs), " online  hosts")

	portsips := make(chan PortIP, len(TCPPorts)*len(onlineIPs))
	// this channel will receive results of scanning
	results := make(chan ScanResult)
	// create a slice to store the results so that they can be sorted later.
	var openports []ScanResult

	// create a pool of workers
	for i := 0; i < cap(portsips); i++ {
		go worker(portsips, results)
	}

	// send ports to be scanned
	go func() {
		for _, ip := range onlineIPs {
			for _, port := range TCPPorts {
				portsips <- PortIP{Port: port, IP: ip}
			}
		}
	}()

	for i := 0; i < len(onlineIPs)*len(TCPPorts); i++ {
		result := <-results
		if result.State == "open" {

			openports = append(openports, result)
		}
	}

	// After all the work has been completed, close the channels
	close(portsips)
	close(results)

	fmt.Println("==================== Priting Results ============================")
	fmt.Println("**** Online Hosts ****")
	for _, onip := range onlineIPs {
		fmt.Println(onip, "is online")
	}

	fmt.Println("**** Opened TCP Ports ****")
	// sort open port numbers
	for _, portip := range openports {
		fmt.Printf("%q:%d is open\n", portip.IP, portip.Port)
	}

	fmt.Println("================= Exporting Results to CSV =========================")

	for _, onlineip := range onlineIPs {
		var CsvTCPOpenPorts string
		for _, portip := range openports {
			if portip.IP == onlineip {
				if len(CsvTCPOpenPorts) == 0 {
					CsvTCPOpenPorts = strconv.Itoa(portip.Port)
				} else {
					CsvTCPOpenPorts = CsvTCPOpenPorts + "|" + strconv.Itoa(portip.Port)
				}

			}
		}

		CsvRecord := []string{onlineip, CsvTCPOpenPorts}
		LocalCsvResults = append(LocalCsvResults, CsvRecord)
	}

	// Getting Info & Stats
	// Get current Date:
	dt := time.Now()
	scanDateTime = dt.Format("02/01/06 15:04")
	fmt.Println("Current date and time is: ", scanDateTime)

	// Calculate duration of the scan
	timeEndScan = time.Now()
	durationScan := timeEndScan.Sub(timeStartScan)
	durationStr := time.Time{}.Add(durationScan)
	scanDurationStr = durationStr.Format("15:04:05")
	fmt.Println("Duration: ", scanDurationStr)

	// Get User Name
	username, _ := executePowerShell("$env:UserName")
	username = removeWhitesString(username)

	// Get FQDN
	fqdn, _ := executePowerShell("[System.Net.Dns]::GetHostByName($env:computerName).HostName")
	fqdn = removeWhitesString(fqdn)

	// Get IP Address
	ipAddr, _ := executePowerShell("[System.Net.Dns]::GetHostByName($env:computerName).AddressList.IPAddressToString")
	ipAddr = removeWhitesString(ipAddr)

	fmt.Println("Scanned By", username)
	fmt.Println("Scanned From", fqdn, "|", ipAddr)

	if machineIsDomainConnected() {
		displayADAssetsResult(ADCsvResults)
		displayADNetworkResult(treeIP)

		nbrAccessibleHostsAD, totalHostsAD = getNumberOfAccessibleHosts(ADCsvResults)
		if totalHostsAD != 0 {
			fmt.Println("AD Accessible ", strconv.Itoa(100*nbrAccessibleHostsAD/totalHostsAD), "%")
			fmt.Println("AD Inaccessible ", strconv.Itoa(100*(totalHostsAD-nbrAccessibleHostsAD)/totalHostsAD), "%")
		}

		nbrServerWithOpenPort, nbrTotalServer = getNumberOfAccessibleHostsByType(ADCsvResults, "server")
		fmt.Println("AD Server Accessible ", strconv.Itoa(nbrAccessibleHostsAsServerAD), "/", strconv.Itoa(totalHostsAD), "%")
		nbrClientWithOpenPort, nbrTotalClient = getNumberOfAccessibleHostsByType(ADCsvResults, "client")
		fmt.Println("AD Client Accessible ", strconv.Itoa(nbrAccessibleHostsAsClientAD), "/", strconv.Itoa(totalHostsAD), "%")

		ADTCPOpenPorts = getTcpOpenPorts(ADCsvResults)
		ADTCPOpenPorts = unique(ADTCPOpenPorts)
		fmt.Println("Number of open ports : ", len(ADTCPOpenPorts), "=> ", ADTCPOpenPorts)

		ADOperatingSystems = getOperatingSystem(ADCsvResults)
		fmt.Println("Number of OS : ", len(ADOperatingSystems), "=> ", ADOperatingSystems)

		for _, openport := range ADTCPOpenPorts {
			serverWithOpenPort, totalServer := getNumberOfHostsWithOpenPortByType(ADCsvResults, openport, "Server")
			clientWithOpenPort, totalClient := getNumberOfHostsWithOpenPortByType(ADCsvResults, openport, "Client")
			fmt.Println("AD Port", openport, " is accessible ", strconv.Itoa(serverWithOpenPort), "/", strconv.Itoa(totalServer), "in Servers")
			fmt.Println("AD Port", openport, " is accessible ", strconv.Itoa(clientWithOpenPort), "/", strconv.Itoa(totalClient), "in Clients")
		}
	}

	nbrAccessibleHostsLoc, totalHostsLoc = getNumberOfAccessibleHosts(LocalCsvResults)
	nbrAssets = strconv.Itoa(nbrAccessibleHostsLoc)
	if totalHostsLoc != 0 {
		fmt.Println("Local Accessible ", strconv.Itoa(100*nbrAccessibleHostsLoc/totalHostsLoc), "%")
		fmt.Println("Local Inaccessible ", strconv.Itoa(100*(totalHostsLoc-nbrAccessibleHostsLoc)/totalHostsLoc), "%")
	}

	LocalTCPOpenPorts = getTcpOpenPorts(LocalCsvResults)
	fmt.Println("Number of open ports : ", len(LocalTCPOpenPorts), "=> ", LocalTCPOpenPorts)

	PrepareIPSummary()
	PrepareOSSummary()
	PreparePortsSummary()

	displayLocalAssetsResult(LocalCsvResults)
	displayLocalNetworkResult(treeIP)

	openbrowser("index.html")

	wg.Wait()
}
