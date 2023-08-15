package conf

import (
	"fmt"
	"log"
	"os"
	"strconv"
	"strings"
)

type dbinfo struct {
	Dbhost string
	Dbuser string
	Dbpwd  string
	Dbname string
}

type mirrcfg struct {
	I_iface string
	In_mac  string
	O_iface string
	O_mac   string
}
type logcfg struct {
	Logway       string
	Logfile      string
	Maxday       int64
	DisableColor bool
	Level        string
}

const config_file = "conf/config.ini"

var DbConnCfg dbinfo
var Logcfg logcfg

var Root_cert_file string
var Root_key_file string

var Mirror_cfg mirrcfg

func LoadConfig() int {

	Root_cert_file = "cert/cld.lstcloud.com.crt"
	Root_key_file = "cert/cld.lstcloud.com.key"
	Logcfg.Logfile = "access_run.log"
	Logcfg.DisableColor = false
	Logcfg.Maxday = 30
	Logcfg.Level = "info"
	Logcfg.Logway = "console"

	file, err := os.Open(config_file)
	if err != nil {
		log.Fatalf("open %s file failed %v", config_file, err)
		return -1
	}
	defer file.Close()

	data := make([]byte, 512) //文件的信息可以读取进一个[]byte切片
	flen, err := file.Read(data)
	if err != nil {
		log.Fatalf("Read %s file failed %v", config_file, err)
		return -1
	}

	var cfg = string(data[0:flen])
	cfgs := strings.Split(cfg, "\n")
	for index, value := range cfgs {
		value = strings.Trim(value, " ")
		if strings.Index(value, "#") == 0 {
			continue
		}
		keys := strings.Split(value, "=")
		fmt.Println(index, "\t", value)

		if len(keys) == 2 {
			keys[0] = strings.TrimSpace(keys[0])
			keys[1] = strings.TrimSpace(keys[1])
			switch keys[0] {
			case "dbhost":
				DbConnCfg.Dbhost = keys[1]
			case "dbuser":
				DbConnCfg.Dbuser = keys[1]
			case "dbpwd":
				DbConnCfg.Dbpwd = keys[1]
			case "dbname":
				DbConnCfg.Dbname = keys[1]
			case "logway":
				Logcfg.Logway = keys[1]
			case "maxday":
				ret, err := strconv.ParseInt(keys[1], 10, 64)
				if err != nil {
					Logcfg.Maxday = 3
				} else {
					Logcfg.Maxday = ret
				}
			case "color":
				ret, err := strconv.ParseBool(keys[1])
				if err != nil {
					Logcfg.DisableColor = false
				} else {
					Logcfg.DisableColor = ret
				}

			case "level":
				Logcfg.Level = keys[1]
			case "logfile":
				Logcfg.Logfile = keys[1]
			case "root_cert_file":
				Root_cert_file = keys[1]
			case "root_key_file":
				Root_key_file = keys[1]

			case "inside_mirror_iface":
				Mirror_cfg.I_iface = keys[1]
			case "inside_mirror_mac":
				Mirror_cfg.In_mac = keys[1]
			case "outside_mirror_iface":
				Mirror_cfg.O_iface = keys[1]
			case "outside_mirror_mac":
				Mirror_cfg.O_mac = keys[1]
			default:
				log.Fatalf("Error:unknow config :%s", keys[0])
			}
		}
	}
	return 1
}
