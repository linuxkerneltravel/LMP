package bpf

import (
	"fmt"
	"os"
	"strconv"
	"strings"
	"syscall"
)

type IntFilterGenerator struct {
	Name    string
	List    []int
	Action  string
	Reverse bool // skip event if `Reverse` is true
}

// Generate generate filter statement for BPF program in C code
func (fg IntFilterGenerator) Generate() string {
	if len(fg.List) == 0 {
		return ""
	}

	filter := ""
	if fg.Reverse == false {
		filter = fmt.Sprintf(" %s != %s", fg.Name, strconv.Itoa(fg.List[0]))
		for _, port := range fg.List[1:] {
			filter += fmt.Sprintf(" && %s != %s", fg.Name, strconv.Itoa(port))
		}
	} else {
		filter = fmt.Sprintf(" %s == %s", fg.Name, strconv.Itoa(fg.List[0]))
		for _, port := range fg.List[1:] {
			filter += fmt.Sprintf(" || %s == %s", fg.Name, strconv.Itoa(port))
		}
	}

	filter = fmt.Sprintf("if (%s) { %s }", filter, fg.Action)
	return filter
}

type FamilyFilterGenerator struct {
	List []string
}

func (fg FamilyFilterGenerator) Generate() string {
	if len(fg.List) == 0 {
		return ""
	}

	filter := GetFamilyFilter(fg.List[0])
	for _, family := range fg.List[1:] {
		filter += GetFamilyFilter(family) // not so formatted here...
	}
	filter = fmt.Sprintf("if (%s) { return 0; }", filter)
	return filter
}

func GetIpv4Filter() string {
	return "if (family != AF_INET) { return 0; }"
}

func GetIpv6Filter() string {
	return "if (family != AF_INET6) { return 0; }"
}

func GetIpv4AndIpv6ReverseFilter() string {
	return "if (family == AF_INET || family == AF_INET6) { return 0; }"
}

func GetFamilyFilter(family string) string {
	family = strings.ToLower(family)

	familyMap := map[string]string{
		"ipv4":  GetIpv4Filter(),
		"ipv6":  GetIpv6Filter(),
		"notip": GetIpv4AndIpv6ReverseFilter(),
	}

	res, ok := familyMap[family]

	if ok != true {
		panic("Family " + family + " not supported")
	}

	return res

}

func GetFilterByParentProcessPidNamespace(rootPid int, pidList []int, reverse bool) (string, error) {
	info, err := os.Stat("/proc/" + strconv.Itoa(rootPid) + "/ns/pid")
	if err != nil {
		return "", fmt.Errorf("get error for /proc/%s/ns/pid: %s", strconv.Itoa(rootPid), err)
	}
	dev := info.Sys().(*syscall.Stat_t).Dev
	ino := info.Sys().(*syscall.Stat_t).Ino

	fg := IntFilterGenerator{
		Name:    "filter_ns.tgid", // TODO: it looks like tgid is the real pid
		List:    pidList,
		Action:  "return 0;",
		Reverse: reverse,
	}

	res := "  struct bpf_pidns_info filter_ns = {};\n\n  if(bpf_get_ns_current_pid_tgid(DEV, INO, &filter_ns, sizeof(struct bpf_pidns_info)))\n    return 0;\n\n  /*FILTER_NS_PID*/"

	res = strings.Replace(res, "DEV", strconv.Itoa(int(dev)), 1)
	res = strings.Replace(res, "INO", strconv.Itoa(int(ino)), 1)
	res = strings.Replace(res, "/*FILTER_NS_PID*/", fg.Generate(), 1)

	return res, nil
}
