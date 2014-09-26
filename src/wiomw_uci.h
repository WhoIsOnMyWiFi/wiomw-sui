#ifndef OPENWRT_SUI_WIOMW_UCI_H
#define OPENWRT_SUI_WIOMW_UCI_H

int set_wiomw_agentkey(const char* agentkey);

int set_wiomw_username(const char* username);

int set_wiomw_passhash(const char* passhash);

int set_wiomw_vals(const char* agentkey, const char* username, const char* passhash);

int get_wiomw_agentkey(char** agentkey);

int get_wiomw_username(char** username);

int get_wiomw_passhash(char** passhash);

int get_wiomw_vals(char** agentkey, char** username, char** passhash);

#endif
