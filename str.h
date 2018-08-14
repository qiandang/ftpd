#ifndef _STR_H_
#define _STR_H_

void str_trim_crlf(char *str);
//quchu\r\n 

void str_split(const char *str, char *left, char *right, char c);
//jiexi ftp mingling yu canshu

int str_all_space(const char *str);
//panduan shi fou wei kong chuan

void str_upper(char *str);
//jiang mingling zhuan huan wei daxie

long long str_to_longlong(const char *str);
//jiang zi fu chuan zhuan huan wei chang zheng xing

unsigned int str_octal_to_uint(const char *str);
//jiang zi fu chuan zhuan hua wei ba jin zhi 

#endif
