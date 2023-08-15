package utils

import (
	"fmt"
	"os"
	"time"

	"log"
)

const (
	proxy_url_record = "proxy_url_record.txt"
)

// 判断所给路径文件/文件夹是否存在
func Exists(path string) bool {
	_, err := os.Stat(path) //os.Stat获取文件信息
	if err != nil {
		if os.IsExist(err) {
			return true
		}
		return false
	}
	return true
}
func BussErrorRecord(format string) {
	var file *os.File
	var err error
	file = nil
	if Exists(proxy_url_record) {
		//使用追加模式打开文件
		file, err = os.OpenFile(proxy_url_record, os.O_APPEND|os.O_WRONLY, os.ModeAppend)
		if err != nil {
			fmt.Println("Open file err =", err)
			return
		}
	} else {
		file, err = os.Create(proxy_url_record) //创建文件
		if err != nil {
			fmt.Println("file create fail")
			return
		}
	}

	if file == nil {
		log.Printf("Create %s failed", proxy_url_record)
		return
	}
	defer file.Close()
	curr := time.Now().Format(time.ANSIC)
	con := fmt.Sprintf("%s %s", curr, format)
	_, err = file.Write([]byte(con))
	if err != nil {
		fmt.Println("Write file err =", err)
		return
	}

}
