#ifndef OPENWRT_SUI_WIFI_H
#define OPENWRT_SUI_WIFI_H

int set_ssid(const char* ssid);

int set_psk(const char* psk);

int set_vals(const char* ssid, const char* psk);

#endif
