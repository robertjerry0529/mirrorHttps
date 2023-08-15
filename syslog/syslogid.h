#ifndef SYSLOG_ID_HEAD
#define SYSLOG_ID_HEAD


#define WX_BASE_ID   0X00001000
#define RS_BASE_ID    0x00002000
#define RSS_BASE_ID   0x00003000
#define BAS_BASE_ID   0x00004000


#define msg_eventId_traffic_info_start		 0x000000
#define msg_eventId_user_account_active_start  0x100000
#define msg_eventId_l3_attack_start			 0x200000
#define msg_eventId_l7_attack_start			 0x300000
#define msg_resource_access_start 		 0x400000
#define msg_system_manage_start				 0x500000
#define msg_rss_rs_notify_start				 0x600000
#define msg_vpn_webproxy_start				 0x700000


#define msg_cluster_group_start  0x800000




#define SYSLOGID_SEC_port_scan  (WX_BASE_ID+msg_eventId_l3_attack_start+1)
#define SYSLOGID_SEC_host_scan  (WX_BASE_ID+msg_eventId_l3_attack_start+2)
#define SYSLOGID_SEC_acl_scan  (WX_BASE_ID+msg_eventId_l3_attack_start+3)


//syslog id
#define SYSLOGID_LOGIN_ERROR   (WX_BASE_ID+msg_eventId_user_account_active_start+1)
#define SYSLOGID_UNTRUST_DEVICE (WX_BASE_ID+msg_eventId_user_account_active_start+2) 
#define SYSLOGID_CLIENT_TUNNEL_TCP (WX_BASE_ID+msg_eventId_user_account_active_start+3) 

#define SYSLOGID_CLIENT_TUNNEL_force_udp (WX_BASE_ID+msg_eventId_user_account_active_start+4) 
#define SYSLOGID_RISK_CONTROL (WX_BASE_ID+msg_eventId_user_account_active_start+5) 
#define SYSLOGID_USER_SECURITY_APPS (WX_BASE_ID+msg_eventId_user_account_active_start+6) 


#define SYSLOG_system_start (WX_BASE_ID+msg_system_manage_start+1) 
#define SYSLOG_system_exit (WX_BASE_ID+msg_system_manage_start+2) 

#define SYSLOG_user_import_event (WX_BASE_ID+msg_system_manage_start+3) 
#define SYSLOG_user_state_event (WX_BASE_ID+msg_system_manage_start+3) 
#define SYSLOG_random_test_event (WX_BASE_ID+msg_system_manage_start+4) 


#define SYSLOGID_CLIENT_ERROR_ADD_SESSION (WX_BASE_ID+msg_system_manage_start+5) 
#define SYSLOGID_USER_CHANGE_PWD_success (WX_BASE_ID+msg_system_manage_start+6) 
#define SYSLOGID_USER_CHANGE_PWD_fail (WX_BASE_ID+msg_system_manage_start+7) 
#define SYSLOGID_USER_CHANGE_info_success (WX_BASE_ID+msg_system_manage_start+8) 
#define SYSLOGID_USER_CHANGE_info_fail (WX_BASE_ID+msg_system_manage_start+9)
#define SYSLOGID_USER_add_node (WX_BASE_ID+msg_system_manage_start+10)
#define SYSLOGID_USER_add_node_failed (WX_BASE_ID+msg_system_manage_start+11)
#define SYSLOGID_LOGIN_MSG_ERROR (WX_BASE_ID+msg_system_manage_start+12)
#define SYSLOGID_BROWSER_REGISTER (WX_BASE_ID+msg_system_manage_start+13)
#define SYSLOGID_ippool_get_failed (WX_BASE_ID+msg_system_manage_start+14)
#define SYSLOGID_ippool_get_success (WX_BASE_ID+msg_system_manage_start+15)

#define SYSLOGID_ldap_socket_error (WX_BASE_ID+msg_system_manage_start+16)
#define SYSLOGID_ldap_result (WX_BASE_ID+msg_system_manage_start+17)
#define SYSLOGID_ldap_sock_msg (WX_BASE_ID+msg_system_manage_start+18)

#define SYSLOGID_event_report_sock_error (WX_BASE_ID+msg_system_manage_start+19)
#define SYSLOGID_event_report_sock_msg (WX_BASE_ID+msg_system_manage_start+20)



#define SYSLOGID_br_sock_error (WX_BASE_ID+msg_system_manage_start+25)
#define SYSLOGID_br_access (WX_BASE_ID+msg_system_manage_start+26)
#define SYSLOGID_br_memcache_info (WX_BASE_ID+msg_system_manage_start+27)
#define SYSLOGID_br_auth_info (WX_BASE_ID+msg_system_manage_start+28)
#define SYSLOGID_br_config (WX_BASE_ID+msg_system_manage_start+29)
#define SYSLOGID_br_process (WX_BASE_ID+msg_system_manage_start+30)

#define SYSLOGID_cls_load (WX_BASE_ID+msg_system_manage_start+40)
#define SYSLOGID_cls_ext_load (WX_BASE_ID+msg_system_manage_start+41)

#define SYSLOGID_config_share (WX_BASE_ID+msg_system_manage_start+42)


#define SYSLOGID_config_ippool (WX_BASE_ID+msg_system_manage_start+43)
#define SYSLOGID_ippool_alloc (WX_BASE_ID+msg_system_manage_start+44)

#define SYSLOG_SYSMEMORY_FAILED (WX_BASE_ID+msg_system_manage_start+45) 
#define SYSLOG_CONFIG_RESOURCE (WX_BASE_ID+msg_system_manage_start+46) 

#define SYSLOG_DBSERVICE_OPFAILED (WX_BASE_ID+msg_system_manage_start+47) 
#define SYSLOG_CONFIG_FILE_MISS (WX_BASE_ID+msg_system_manage_start+48) 
#define SYSLOG_CONFIG_FILE_LOAD (WX_BASE_ID+msg_system_manage_start+49) 
#define SYSLOG_CONFIG_PROCESS (WX_BASE_ID+msg_system_manage_start+50) 
#define SYSLOG_CONFIG_SOCK_FAILED (WX_BASE_ID+msg_system_manage_start+51) 
#define SYSLOG_CONFIG_SYNC_FILE (WX_BASE_ID+msg_system_manage_start+52) 
#define SYSLOG_CONFIG_DB_CFG (WX_BASE_ID+msg_system_manage_start+53) 
#define SYSLOG_database_con_failed (WX_BASE_ID+msg_system_manage_start+54) 
#define SYSLOG_database_get_vip_failed (WX_BASE_ID+msg_system_manage_start+55) 
#define SYSLOG_database_vip_exhausted (WX_BASE_ID+msg_system_manage_start+56) 
#define SYSLOG_database_check_history_online (WX_BASE_ID+msg_system_manage_start+57) 
#define SYSLOG_database_load_spa (WX_BASE_ID+msg_system_manage_start+58) 
#define SYSLOG_database_username_sync (WX_BASE_ID+msg_system_manage_start+59) 
#define SYSLOG_database_username_sync_failed (WX_BASE_ID+msg_system_manage_start+60) 

#define SYSLOG_config_license (WX_BASE_ID+msg_system_manage_start+61) 

#define SYSLOG_config_subobj_exceed (WX_BASE_ID+msg_system_manage_start+62) 

#define SYSLOG_config_get_ifaddr (WX_BASE_ID+msg_system_manage_start+63) 

#define SYSLOG_system_signal_handler (WX_BASE_ID+msg_system_manage_start+64) 
#define SYSLOG_system_ifcfg_file (WX_BASE_ID+msg_system_manage_start+65) 
#define SYSLOG_license_socket (WX_BASE_ID+msg_system_manage_start+66)

#define SYSLOG_config_operate (WX_BASE_ID+msg_system_manage_start+67)
#define SYSLOG_user_trust_level_change (WX_BASE_ID+msg_system_manage_start+68)
#define SYSLOG_user_bind_change (WX_BASE_ID+msg_system_manage_start+69)
#define SYSLOG_user_blocked (WX_BASE_ID+msg_system_manage_start+70)
#define SYSLOG_user_enabled (WX_BASE_ID+msg_system_manage_start+71)
#define SYSLOG_user_info_change (WX_BASE_ID+msg_system_manage_start+72)
#define SYSLOG_user_device_register (WX_BASE_ID+msg_system_manage_start+73)

#define SYSLOG_user_access_ctx (WX_BASE_ID+msg_system_manage_start+74)
#define SYSLOG_spa_config_wrong (WX_BASE_ID+msg_system_manage_start+75)
#define SYSLOG_spa_relay (WX_BASE_ID+msg_system_manage_start+76)
#define SYSLOG_spa_wrong_hash (WX_BASE_ID+msg_system_manage_start+77)
#define SYSLOG_spa_miss (WX_BASE_ID+msg_system_manage_start+78)
#define SYSLOG_spa_mem (WX_BASE_ID+msg_system_manage_start+79)



#define SYSLOG_dpdk_deploy (WX_BASE_ID+msg_system_manage_start+80) 

#define SYSLOG_user_session_release (WX_BASE_ID+msg_system_manage_start+82) 
#define SYSLOG_user_spa_wrong (WX_BASE_ID+msg_system_manage_start+83) 

#define SYSLOG_user_cert_login (WX_BASE_ID+msg_system_manage_start+84) 



#define SYSLOG_CONN_MEM_FAILED (WX_BASE_ID+msg_system_manage_start+90) 
#define SYSLOG_TIME_MEM_FAILED (WX_BASE_ID+msg_system_manage_start+91) 
#define SYSLOG_hostobj_table_FAILED (WX_BASE_ID+msg_system_manage_start+92) 


#define SYSLOG_host_access (WX_BASE_ID+msg_system_manage_start+99) 

#define SYSLOG_forword_ftp (WX_BASE_ID+msg_system_manage_start+100) 

#define SYSLOG_forword_udp_con_limit (WX_BASE_ID+msg_system_manage_start+101) 

#define SYSLOG_forword_hostobj_limit (WX_BASE_ID+msg_system_manage_start+102) 


#define SYSLOG_forword_hostobj_create (WX_BASE_ID+msg_system_manage_start+103) 
#define SYSLOG_forword_hostobj_create_failed (WX_BASE_ID+msg_system_manage_start+104) 


#define SYSLOG_forword_udp_session (WX_BASE_ID+msg_system_manage_start+105) 
#define SYSLOG_forword_tcp_con_limit (WX_BASE_ID+msg_system_manage_start+106) 

#define SYSLOG_forword_bad_iphead (WX_BASE_ID+msg_system_manage_start+107) 
#define SYSLOG_forword_create_tcp_session (WX_BASE_ID+msg_system_manage_start+108) 

#define SYSLOG_spa_cleaning (WX_BASE_ID+msg_system_manage_start+109)
#define SYSLOG_spa_hash_insert (WX_BASE_ID+msg_system_manage_start+110)
#define SYSLOG_spa_device_miss (WX_BASE_ID+msg_system_manage_start+111)
#define SYSLOG_spa_seed_generate (WX_BASE_ID+msg_system_manage_start+112)
#define SYSLOG_spa_white_item_mem (WX_BASE_ID+msg_system_manage_start+113)
#define SYSLOG_spa_white_hash_tbl (WX_BASE_ID+msg_system_manage_start+114)


#define SYSLOG_USER_ACTIVE_RISK  (WX_BASE_ID+msg_system_manage_start+115)
#define SYSLOG_USER_SECURITY_LEVEL_CHANGE  (WX_BASE_ID+msg_system_manage_start+116)
#define SYSLOG_forword_tcp_session (WX_BASE_ID+msg_system_manage_start+117) 
#define SYSLOG_forword_create_udp_session (WX_BASE_ID+msg_system_manage_start+118) 


#define SYSLOG_ctrl_sslctx_cert (WX_BASE_ID+msg_system_manage_start+198) 

#define SYSLOG_ctrl_sslctx (WX_BASE_ID+msg_system_manage_start+199) 

#define SYSLOG_ctrl_server_socket (WX_BASE_ID+msg_system_manage_start+200) 
#define SYSLOG_ctrl_server_accept (WX_BASE_ID+msg_system_manage_start+201) 
#define SYSLOG_ctrl_tcp_tunnel (WX_BASE_ID+msg_system_manage_start+202) 
#define SYSLOG_ctrl_client_cert_expire (WX_BASE_ID+msg_system_manage_start+203) 
#define SYSLOG_ctrl_client_cert_auth (WX_BASE_ID+msg_system_manage_start+204) 
#define SYSLOG_ctrl_server_config (WX_BASE_ID+msg_system_manage_start+205) 
#define SYSLOG_ctrl_session_memory_fail (WX_BASE_ID+msg_system_manage_start+206) 
#define SYSLOG_ctrl_l3service_start_fail (WX_BASE_ID+msg_system_manage_start+207) 
#define SYSLOG_ctrl_l3service_start_ok (WX_BASE_ID+msg_system_manage_start+208) 



#define SYSLOG_user_session_sec_ctx (WX_BASE_ID+msg_system_manage_start+210) 
#define SYSLOG_user_session_device_bind (WX_BASE_ID+msg_system_manage_start+211)  
#define SYSLOG_user_session_replace (WX_BASE_ID+msg_system_manage_start+212)  
#define SYSLOG_user_session_memory (WX_BASE_ID+msg_system_manage_start+213)  
#define SYSLOG_user_session_getacl (WX_BASE_ID+msg_system_manage_start+214)  
#define SYSLOG_user_session_offline (WX_BASE_ID+msg_system_manage_start+215)  

#define SYSLOG_tcp_tunnel_socket (WX_BASE_ID+msg_system_manage_start+216)  
#define SYSLOG_tcp_tunnel_mem (WX_BASE_ID+msg_system_manage_start+217)  

#define SYSLOG_time_ctrl_mem (WX_BASE_ID+msg_system_manage_start+218)  
#define SYSLOG_trust_process_mem (WX_BASE_ID+msg_system_manage_start+219)

#define SYSLOG_trust_process_cfg (WX_BASE_ID+msg_system_manage_start+220)

#define SYSLOG_user_session_release_error (WX_BASE_ID+msg_system_manage_start+221)  
#define SYSLOG_user_import_file_error  (WX_BASE_ID+msg_system_manage_start+222) 


#define SYSLOG_route_cfg (WX_BASE_ID+msg_system_manage_start+301)  

#define SYSLOG_sso_socket (WX_BASE_ID+msg_system_manage_start+300)  

#define SYSLOG_user_unlock (WX_BASE_ID+msg_system_manage_start+301)  
#define SYSLOG_user_lock (WX_BASE_ID+msg_system_manage_start+302)  
#define SYSLOG_user_disable (WX_BASE_ID+msg_system_manage_start+303)   

#define SYSLOG_mng_upgrade_file_failed (WX_BASE_ID+msg_system_manage_start+304)   
#define SYSLOG_SYSTEM_GETHOSTNAME_FAILED (WX_BASE_ID+msg_system_manage_start+305)   
#define SYSLOG_SSO_AUTH (WX_BASE_ID+msg_system_manage_start+306)   
#define SYSLOG_CERT_OCSP_AUTH (WX_BASE_ID+msg_system_manage_start+307)   

#define SYSLOG_CERT_SERVICE (WX_BASE_ID+msg_system_manage_start+500)   

#define SYSLOG_ZIP_LOGO_FAILED (WX_BASE_ID+msg_system_manage_start+501)  
#define SYSLOG_SYNC_LOGO_FAILED (WX_BASE_ID+msg_system_manage_start+502)  
#define SYSLOG_LOGO_FILE_CORRUPT (WX_BASE_ID+msg_system_manage_start+503)  
#define SYSLOG_CLIENT_CHANGE_PWD (WX_BASE_ID+msg_system_manage_start+504)  
#define SYSLOG_CLIENT_SEND_SMS (WX_BASE_ID+msg_system_manage_start+505)  


#define SYSLOG_SYSTEM_CONTEXT_OP_EVENT (WX_BASE_ID+msg_system_manage_start+506)  

#define SYSLOG_user_cert_ctrl (WX_BASE_ID+msg_system_manage_start+507) 

#define SYSLOG_dpdk_rcu (WX_BASE_ID+msg_system_manage_start+508) 

#define SYSLOG_fprs_connection (WX_BASE_ID+msg_system_manage_start+509) 
#define SYSLOG_user_info_ctrl (WX_BASE_ID+msg_system_manage_start+510) 





#define SYSLOG_WEBVPN_accept_failed    (WX_BASE_ID+msg_vpn_webproxy_start+1)   
#define SYSLOG_WEBVPN_accept_success    (WX_BASE_ID+msg_vpn_webproxy_start+2) 
#define SYSLOG_WEBVPN_memory_event    (WX_BASE_ID+msg_vpn_webproxy_start+3)
#define SYSLOG_WEBVPN_CLIENT_PROXY  (WX_BASE_ID+msg_vpn_webproxy_start+4)
#define SYSLOG_WEBVPN_SOCKET_EVENT  (WX_BASE_ID+msg_vpn_webproxy_start+5)



#define SYSLOG_ACCESS_USER_REPLATE (WX_BASE_ID+msg_resource_access_start + 1)
#define SYSLOG_ACCESS_USER_NO_RELATE_CERT (WX_BASE_ID+msg_resource_access_start + 2)
#define SYSLOG_ACCESS_USER_INGORE_DEVICE_BIND_REQUIRE (WX_BASE_ID+msg_resource_access_start + 3)
#define SYSLOG_port_table  (WX_BASE_ID+msg_resource_access_start + 4)
#define SYSLOG_service_map  (WX_BASE_ID+msg_resource_access_start + 5)
#define SYSLOG_domain_table  (WX_BASE_ID+msg_resource_access_start + 5)



#define SYSLOG_GROUP_CONNECTION (WX_BASE_ID+msg_cluster_group_start + 1) 
#define SYSLOG_GROUP_NODE_SYNC (WX_BASE_ID+msg_cluster_group_start + 2) 
#define SYSLOG_GROUP_SPA_SYNC (WX_BASE_ID+msg_cluster_group_start + 3) 
#define SYSLOG_GROUP_CFG_SYNC (WX_BASE_ID+msg_cluster_group_start + 4)

#define SYSLOG_ACCESS_PATH_REFUSED (WX_BASE_ID+msg_cluster_group_start + 5)
#define SYSLOG_ACCESS_PATH_PERMIT (WX_BASE_ID+msg_cluster_group_start + 6)


#define SYSLOG_USER_BIND_INFO_SYNC (WX_BASE_ID+msg_cluster_group_start + 7)

#endif
