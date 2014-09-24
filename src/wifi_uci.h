#ifndef OPENWRT_SUI_WIFI_UCI_H
#define OPENWRT_SUI_WIFI_UCI_H

int set_wifi_ssid(const char* ssid);

int set_wifi_psk(const char* psk);

int set_wifi_vals(const char* ssid, const char* psk);

int get_wifi_ssid(char** ssid);

int get_wifi_psk(char** psk);

int get_wifi_vals(char** ssid, char** psk);

#endif
