package services

import (
	"errors"
	"fmt"
	"sslproxy/conf"
	"strconv"
	"strings"

	"github.com/gomodule/redigo/redis"
)

/*访问redis，获得数据*/
func remote_access_get(remoteAddr string) (accessInfo, error) {
	var info accessInfo
	var dbhost string
	if !strings.Contains(conf.DbConnCfg.Dbhost, ":") {
		dbhost = fmt.Sprintf("%s:6379", conf.DbConnCfg.Dbhost)
	} else {
		dbhost = conf.DbConnCfg.Dbhost
	}
	c, err := redis.Dial("tcp", dbhost)
	if err != nil {
		fmt.Println("conn redis failed, err:", err)
		return info, err
	}
	defer c.Close()
	res, err := redis.String(c.Do("Get", remoteAddr))
	if err != nil {
		fmt.Println(err)

		return info, err
	}

	fmt.Println(res)
	//domain:nat_faddr:fport:raw_laddr:raw_faddr
	addr := strings.Split(res, ":")
	if len(addr) == 5 {
		info.Domain = addr[0]
		info.RemoteIp = addr[1]
		val, err := strconv.Atoi(addr[2])
		if err != nil {
			return info, err
		} else {
			info.RemotePort = val
		}
		info.Raw_lip = addr[3]
		info.Raw_fip = addr[4]
		info.LocalIp = info.Raw_lip
	} else {
		return info, errors.New("remote info format error")
	}
	if info.LocalPort == 0 {
		info.LocalPort = 443
	}

	return info, nil
}
