
/*
 * (C) 2010-2011 Alibaba Group Holding Limited
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 *
 */

#include <stddef.h>
#include "cJSON.h"
#include "tsar.h"
#include <sys/un.h>
#include <arpa/inet.h>
#include <netinet/in.h>
#include <string.h>


#define LF     (u_char) '\n'
#define CR     (u_char) '\r'
#define CRLF   "\r\n"
#define CRLFCRLF "\r\n\r\n"
#define STATS_TEST_SIZE (sizeof(struct stats_bkb))

static const char *bkb_usage = "    --bkb               bkb waf information";

/*
 * temp structure for collection infomation.
 */
struct stats_bkb {
    unsigned long long    totalcnt;
    unsigned long long    maxdelay;
    unsigned long long    trigger;
    unsigned long long    avgdelay; //us
    unsigned long long    rule_version;
    unsigned long long    ip_version;
    int                   run;
    int                   dry;
};

struct hostinfo {
    char *host;
    int   port;
    char *server_name;
    char *uri;
};

/* Structure for tsar */
static struct mod_info bkb_info[] = {
    {" count", DETAIL_BIT,  0,  STATS_NULL},
    {"   max", DETAIL_BIT,  0,  STATS_NULL},
    {"   hit", SUMMARY_BIT,  0,  STATS_NULL},
    {"   hps", DETAIL_BIT,  0,  STATS_NULL},
    {"   avg", SUMMARY_BIT,  0,  STATS_NULL},
    {" r_ver", DETAIL_BIT,  0,  STATS_NULL},
    {"ip_ver", DETAIL_BIT,  0,  STATS_NULL},
    {"   run", DETAIL_BIT,  0,  STATS_NULL},
    {"   dry", DETAIL_BIT,  0,  STATS_NULL},
};

static void
init_bkb_host_info(struct hostinfo *p)
{
    char *port;

    p->host = getenv("BKB_TSAR_HOST");
    p->host = p->host ? p->host : "127.0.0.1";

    port = getenv("BKB_TSAR_PORT");
    p->port = port ? atoi(port) : 80;

    p->uri = getenv("BKB_TSAR_URI");
    p->uri = p->uri ? p->uri : "/waf";

    p->server_name = getenv("BKB_TSAR_SERVER_NAME");
    p->server_name = p->server_name ? p->server_name : "bkb";
}

static void
read_bkb_stats(struct module *mod, const char *parameter)
{
    /* parameter actually equals to mod->parameter */
    char                buf[LEN_4096], request[LEN_4096];
    int                 write_flag = 0, addr_len, domain;
    int                 m, sockfd, send, pos;
    void               *addr;
    cJSON              *root, *item;
    struct hostinfo     hinfo;
    struct stats_bkb    st_bkb;
    struct sockaddr_in  servaddr;
    struct sockaddr_un  servaddr_un;


    init_bkb_host_info(&hinfo);
    if (atoi(parameter) != 0) {
       hinfo.port = atoi(parameter);
    }

    memset(buf, 0, sizeof(buf));
    memset(&st_bkb, 0, sizeof(struct stats_bkb));

    if (*hinfo.host == '/') {
        addr = &servaddr_un;
        addr_len = sizeof(servaddr_un);
        bzero(addr, addr_len);
        domain = AF_LOCAL;
        servaddr_un.sun_family = AF_LOCAL;
        strncpy(servaddr_un.sun_path, hinfo.host, sizeof(servaddr_un.sun_path) - 1);

    } else {
        addr = &servaddr;
        addr_len = sizeof(servaddr);
        bzero(addr, addr_len);
        domain = AF_INET;
        servaddr.sin_family = AF_INET;
        servaddr.sin_port = htons(hinfo.port);
        inet_pton(AF_INET, hinfo.host, &servaddr.sin_addr);
    }

    if ((sockfd = socket(domain, SOCK_STREAM, 0)) == -1) {
        goto writebuf;
    }
    sprintf(request,
        "GET %s HTTP/1.0\r\n"
        "Host: %s\r\n"
        "Accept:*/*\r\n"
        "Connection: Close\r\n\r\n",
        hinfo.uri, hinfo.server_name);

    if ((m = connect(sockfd, (struct sockaddr *) addr, addr_len)) == -1 ) {
        goto writebuf;
    }

    if ((send = write(sockfd, request, strlen(request))) == -1) {
        goto writebuf;
    }

    m = read(sockfd, buf, LEN_4096);
    if (m == 0) {
        goto writebuf;
    }

    buf[m] = '\0';
    char *str = strstr(buf, CRLFCRLF);

    if (str == NULL) {
        goto writebuf;
    }

    root = cJSON_Parse(str+strlen(CRLFCRLF));

    if (root == NULL) {
        goto writebuf;
    }

    item = cJSON_GetObjectItem(root, "totalcnt");
    if (item == NULL) {
        goto writebuf;
    }
    st_bkb.totalcnt = item->valueint;

    item = cJSON_GetObjectItem(root, "maxdelay");
    if (item == NULL) {
        goto writebuf;
    }
    st_bkb.maxdelay = item->valueint;

    item = cJSON_GetObjectItem(root, "trigger");
    if (item == NULL) {
        goto writebuf;
    }
    st_bkb.trigger = item->valueint;

    item = cJSON_GetObjectItem(root, "delay");
    if (item == NULL) {
        goto writebuf;
    }
    st_bkb.avgdelay= item->valueint;

    item = cJSON_GetObjectItem(root, "rule_version");
    if (item == NULL) {
        goto writebuf;
    }
    st_bkb.rule_version = item->valueint;

    item = cJSON_GetObjectItem(root, "ip_version");
    if (item == NULL) {
        goto writebuf;
    }
    st_bkb.ip_version = item->valueint;

    item = cJSON_GetObjectItem(root, "run");
    if (item == NULL) {
        goto writebuf;
    }
    st_bkb.run = item->valueint;

    item = cJSON_GetObjectItem(root, "dry");
    if (item == NULL) {
        goto writebuf;
    }
    st_bkb.dry = item->valueint;

    write_flag = 1;

writebuf:

    if (sockfd != -1) {
        close(sockfd);
    }

    if (write_flag) {
        pos = sprintf(buf, "%lld,%lld,%lld,%lld,%lld,%lld,%lld,%d,%d",
                st_bkb.totalcnt,
                st_bkb.maxdelay / 1000,
                st_bkb.trigger,
                st_bkb.trigger,
                st_bkb.avgdelay,
                st_bkb.rule_version,
                st_bkb.ip_version,
                st_bkb.run,
                st_bkb.dry
                 );
        buf[pos] = '\0';
        set_mod_record(mod, buf);
    }
}

static void
set_bkb_record(struct module *mod, double st_array[],
    U_64 pre_array[], U_64 cur_array[], int inter)
{
    int i;
    /* set st record */
    for (i = 0; i < mod->n_col; i++) {
        if ( i == 3) {
            st_array[i] = (cur_array[i] - pre_array[i]) * 1.0 / inter;
        } else if (i == 4) {
            st_array[i] = cur_array[i] / 1000.00;
        } else {
            st_array[i] = cur_array[i];
        }
    }
}

/* register mod to tsar */
void
mod_register(struct module *mod)
{
    register_mod_fields(mod, "--bkb", bkb_usage, bkb_info, 9, read_bkb_stats, set_bkb_record);
}
