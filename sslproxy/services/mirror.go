package services

/*
#cgo CFLAGS: -I../../mirror
#cgo LDFLAGS: -L  ../../mirror -lmirror
#include "stdlib.h"
#include "pktout.h"
*/
import "C"
import (
	"unsafe"
)

func Mirror_cfg_set(i_ifname string, i_mac string, o_ifname string, o_mac string) int {

	name1 := C.CString(i_ifname)
	mac1 := C.CString(i_mac)
	name2 := C.CString(o_ifname)
	mac2 := C.CString(o_mac)

	ret := C.mirror_cfg_set(name1, mac1, name2, mac2)
	defer C.free(unsafe.Pointer(name1))
	defer C.free(unsafe.Pointer(mac1))
	defer C.free(unsafe.Pointer(name2))
	defer C.free(unsafe.Pointer(mac2))
	return int(ret)
}

func Mirror_start() int {
	ret := C.mirror_start()
	return int(ret)
}

func mirror_pkt_send(data []byte, len int, dir int,
	sip string, sport uint16, dip string, dport uint16) {

	//td := C.CBytes(data) //转成C数组
	csip := C.CString(sip)
	cdip := C.CString(dip)

	C.mirror_pkt_send(unsafe.Pointer(&data[0]), C.int(len), C.int(dir), csip, C.ushort(sport), cdip, C.ushort(dport))
	//C.free(td)
	C.free(unsafe.Pointer(csip))
	C.free(unsafe.Pointer(cdip))
}

func mirror_connection_end(dir int,
	sip string, sport uint16, dip string, dport uint16) {
	csip := C.CString(sip)
	cdip := C.CString(dip)
	C.mirror_connection_end(C.int(dir), csip, C.ushort(sport), cdip, C.ushort(dport))
	C.free(unsafe.Pointer(csip))
	C.free(unsafe.Pointer(cdip))
}
