#define _GNU_SOURCE
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <string.h>
#include <strings.h>
#include <signal.h>
#include <locale.h>
#include <dirent.h>
#include <pwd.h>
#include <sys/mman.h>
#include <sys/time.h>
#include <sys/resource.h>
#include <arpa/inet.h>
#include <netdb.h>
#include <sbase.h>
#ifdef HAVE_ZLIB
#include <zlib.h>
#endif
#ifdef HAVE_BZ2LIB
#include <bzlib.h>
#endif
#include "iniparser.h"
#include "xssl.h"
#include "http.h"
#include "mime.h"
#include "mtrie.h"
#include "stime.h"
#include "logger.h"
#include "message.h"
#define XHTTPD_VERSION 		    "1.0.4"
#define HTTP_RESP_OK            "HTTP/1.1 200 OK"
#define HTTP_BAD_REQUEST        "HTTP/1.1 400 Bad Request\r\nContent-Length: 0\r\n\r\n"
#define HTTP_NOT_FOUND          "HTTP/1.1 404 Not Found\r\nContent-Length: 0\r\n\r\n" 
#define HTTP_NOT_MODIFIED       "HTTP/1.1 304 Not Modified\r\nContent-Length: 0\r\n\r\n"
#define HTTP_NO_CONTENT         "HTTP/1.1 206 No Content\r\nContent-Length: 0\r\n\r\n"
#define HTTP_LINE_SIZE          65536
#define HTTP_VIEW_SIZE          131072
#define HTTPD_TIMEOUT           10000000
#define LL(x) ((long long)x)
#define UL(x) ((unsigned long int)x)
static const char *http_encodings[] = {"deflate", "gzip", "bzip2", "compress"}; 
static SBASE *sbase = NULL;
static SERVICE *httpd = NULL;
static SERVICE *httpsd = NULL;
static dictionary *dict = NULL;
static char *httpd_home = "/tmp/xhttpd/html";
static int http_indexes_view = 0;
static char *http_indexes[HTTP_INDEX_MAX];
static int nindexes = 0;
static char *http_default_charset = "UTF-8";
static char *httpd_access_log_dir = "/tmp/xhttpd/log";
static int httpd_compress = 1;
static char *httpd_compress_cachedir = "/tmp/xhttpd/cache";
static HTTP_VHOST httpd_vhosts[HTTP_VHOST_MAX];
static int nvhosts = 0;
static int httpd_proxy_timeout = 0;
static void *namemap = NULL;
static void *hostmap = NULL;
static void *urlmap = NULL;
static void *http_headers_map = NULL;
static void *default_logger = NULL;
static int xhttpd_SSL_hostname_callback(void *s, int *ad, void *arg)
{
#ifdef HAVE_SSL
    char *servername = SSL_get_servername((SSL *)s, TLSEXT_NAMETYPE_host_name);
    int i = 0;
    if (servername && (i = (mtrie_get(namemap, servername, strlen(servername) - 1))) >= 0
            && httpd_vhosts[i].s_ctx)
    {
        //fprintf(stdout, "servername:%s %p\n", servername, httpd_vhosts[i].s_ctx);
        SSL_set_SSL_CTX((SSL *)s, XSSL_CTX(httpd_vhosts[i].s_ctx));
    }
    return SSL_TLSEXT_ERR_OK;
#else
    return 0;
#endif
}
/* mkdir recursive */
int xhttpd_mkdir(char *path, int mode)
{
    char *p = NULL, fullpath[HTTP_PATH_MAX];
    int ret = 0, level = -1;
    struct stat st;

    if(path)
    {
        strcpy(fullpath, path);
        p = fullpath;
        while(*p != '\0')
        {
            if(*p == '/' )
            {
                while(*p != '\0' && *p == '/' && *(p+1) == '/')++p;
                if(level > 0)
                {
                    *p = '\0';
                    memset(&st, 0, sizeof(struct stat));
                    ret = stat(fullpath, &st);
                    if(ret == 0 && !S_ISDIR(st.st_mode)) return -1;
                    if(ret != 0 && mkdir(fullpath, mode) != 0) return -1;
                    *p = '/';
                }
                level++;
            }
            ++p;
        }
        return 0;
    }
    return -1;
}

int http_proxy_packet_reader(CONN *conn, CB_DATA *buffer)
{
    char *p = NULL, *end = NULL;
    int n = -1;

    if(conn && buffer && buffer->ndata > 0 && (p = buffer->data)
            && (end = (buffer->data + buffer->ndata)))
    {
        while(p < end)
        {
            if(p < (end - 3) && *p == '\r' && *(p+1) == '\n' && *(p+2) == '\r' && *(p+3) == '\n')
            {
                n = p + 4 - buffer->data;
                break;
            }
            else ++p;
        }
    }
    return n;
}

/* xhttpd packet reader */
int xhttpd_packet_reader(CONN *conn, CB_DATA *buffer)
{
    /*
    char *s = NULL, buf[1024];
    int x = 0, n = 0; 
    s = "sdklhafkllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllhflkdfklasdjfkldsakfldsalkfkasdfjksdjfkdasjfklasdjfklsdjfklsjdkfljdssssssssssssssssssssssssssssssssssssssssldkfjsakldjflkajsdfkljadkfjkldajfkljd";x = strlen(s);n = sprintf(buf, "HTTP/1.0 200 OK\r\nContent-Length:%d\r\n\r\n", 0);conn->push_chunk(conn, buf, n);return 0;
    */
    return 0;
}

/* xhttpd index view */
int xhttpd_index_view(CONN *conn, HTTP_REQ *http_req, char *dir, char *path)
{
    char buf[HTTP_BUF_SIZE], url[HTTP_PATH_MAX], line[HTTP_PATH_MAX],
         *p = NULL, *e = NULL, *pp = NULL;
    int len = 0, n = 0, keepalive = 0;
    struct dirent *ent = NULL;
    unsigned char *s = NULL;
    DIR *dirp = NULL, *newdir = NULL;
    CB_DATA *block = NULL;

    if(conn && dir && path && (dirp = opendir(dir)))
    {
        if((block = conn->newchunk(conn, HTTP_VIEW_SIZE)))
        {
            p = pp = block->data;
            p += sprintf(p, "<html><head><title>Indexes Of %s</title>"
                    "<head><body><h1 align=center>xhttpd</h1>", path);
            p += sprintf(p, "<hr noshade><table><tr align=left>"
                    "<th width=500>Name</th></tr>");
            if(path[1] != '\0') p += sprintf(p, "<tr><td><a href='../'>..</a></td></tr>");
            while((ent = readdir(dirp)) != NULL)
            {
                if(ent->d_name[0] != '.' && ent->d_reclen > 0)
                {
                    p += sprintf(p, "<tr>");
                    s = (unsigned char *)ent->d_name;
                    e = url;
                    while(*s != '\0') 
                    {
                        if(*s == 0x20 || *s > 127)
                        {
                            e += sprintf(e, "%%%02x", *s++);
                        }else *e++ = *s++;
                    }
                    *e = '\0';
                    sprintf(line, "%s/%s", dir, ent->d_name);
                    if(ent->d_type == DT_DIR || (newdir = opendir(line)))
                    {
                        if(newdir){closedir(newdir);newdir = NULL;}
                        p += sprintf(p, "<td><a href='%s%s/' >%s/</a></td>", 
                                path, url, ent->d_name);
                    }
                    else
                    {
                        p += sprintf(p, "<td><a href='%s' >%s</a></td>", 
                                url, ent->d_name);
                    }
                    p += sprintf(p, "</tr>");
                }
            }
            p += sprintf(p, "</table>");
            p += sprintf(p, "<hr noshade>");
            p += sprintf(p, "<script src=\"http://s5.cnzz.com/stat.php?id=3705266&web_id=3705266&show=pic2\" language=\"JavaScript\"></script>");
            p += sprintf(p, "<em></body></html>");
            len = (p - pp);
            p = buf;
            p += sprintf(p, "HTTP/1.1 200 OK\r\nContent-Length:%lld\r\n"
                    "Content-Type: text/html; charset=%s\r\n",
                    LL(len), http_default_charset);
            if((n = http_req->headers[HEAD_GEN_CONNECTION]) > 0)
            {
                p += sprintf(p, "Connection: %s\r\n", http_req->hlines + n);
                if(strcasestr(http_req->hlines + n, "close") == NULL )
                    keepalive = 1;
            }
            else 
            {
                p += sprintf(p, "Connection: close\r\n");
            }
            p += sprintf(p, "Date: ");p += GMTstrdate(time(NULL), p);p += sprintf(p, "\r\n");
            p += sprintf(p, "Server: xhttpd/%s\r\n\r\n", XHTTPD_VERSION);
            conn->push_chunk(conn, buf, p - buf);
            if(conn->send_chunk(conn, block, len) != 0)
                conn->freechunk(conn, block);
            //fprintf(stdout, "buf:%s pp:%s\n", buf, pp);
            if(!keepalive) conn->over(conn);
            else conn->set_timeout(conn, HTTPD_TIMEOUT);
        }
        closedir(dirp);
        return 0;
    }
    return -1;
}
#ifdef HAVE_ZLIB
int xhttpd_gzip(unsigned char **zstream, unsigned char *in, int inlen, time_t mtime)
{
    unsigned char *c = NULL, *out = NULL;
    unsigned long crc = 0;
    int outlen = 0;
    z_stream z = {0};

    if(in && inlen > 0)
    {
        z.zalloc = Z_NULL;
        z.zfree = Z_NULL;
        z.opaque = Z_NULL;
        if(deflateInit2(&z, Z_DEFAULT_COMPRESSION, Z_DEFLATED, 
                    -MAX_WBITS, 8, Z_DEFAULT_STRATEGY) != Z_OK)
        {
            return -1;
        }
        z.next_in = (unsigned char *)in;
        z.avail_in = inlen;
        z.total_in = 0;
        outlen = (inlen * 1.1) + 12 + 18;
        if((*zstream = out = (unsigned char *)calloc(1, outlen)))
        {
            c = out;
            c[0] = 0x1f;
            c[1] = 0x8b;
            c[2] = Z_DEFLATED;
            c[3] = 0; /* options */
            c[4] = (mtime >>  0) & 0xff;
            c[5] = (mtime >>  8) & 0xff;
            c[6] = (mtime >> 16) & 0xff;
            c[7] = (mtime >> 24) & 0xff;
            c[8] = 0x00; /* extra flags */
            c[9] = 0x03; /* UNIX */
            z.next_out = out + 10;
            z.avail_out = outlen - 10 - 8;
            z.total_out = 0;
            if(deflate(&z, Z_FINISH) != Z_STREAM_END)
            {
                deflateEnd(&z);
                free(*zstream);
                *zstream = NULL;
                return -1;
            }
            //crc
            crc = http_crc32(in, inlen);
            c = *zstream + 10 + z.total_out;
            c[0] = (crc >>  0) & 0xff;
            c[1] = (crc >>  8) & 0xff;
            c[2] = (crc >> 16) & 0xff;
            c[3] = (crc >> 24) & 0xff;
            c[4] = (z.total_in >>  0) & 0xff;
            c[5] = (z.total_in >>  8) & 0xff;
            c[6] = (z.total_in >> 16) & 0xff;
            c[7] = (z.total_in >> 24) & 0xff;
            outlen = (10 + 8 + z.total_out);
            if(deflateEnd(&z) != Z_OK)
            {
                free(*zstream);
                *zstream = NULL;
                return -1;
            }
            return outlen;
        }
    }
    return -1;
}

/* deflate */
int xhttpd_deflate(unsigned char **zstream, unsigned char *in, int inlen)
{
    unsigned char *out = NULL;
    z_stream z = {0};
    int outlen = 0;

    if(in && inlen > 0)
    {
        z.zalloc = Z_NULL;
        z.zfree = Z_NULL;
        z.opaque = Z_NULL;
        if(deflateInit2(&z, Z_DEFAULT_COMPRESSION, Z_DEFLATED, 
                    -MAX_WBITS, 8, Z_DEFAULT_STRATEGY) != Z_OK)
        {
            return -1;
        }
        z.next_in = (unsigned char *)in;
        z.avail_in = inlen;
        z.total_in = 0;
        outlen = (inlen * 1.1) + 12 + 18;
        if((*zstream = out = (unsigned char *)calloc(1, outlen)))
        {
            z.next_out = out;
            z.avail_out = outlen;
            z.total_out = 0;
            if(deflate(&z, Z_FINISH) != Z_STREAM_END)
            {
                deflateEnd(&z);
                free(*zstream);
                *zstream = NULL;
                return -1;
            }
            outlen = z.total_out;
            if(deflateEnd(&z) != Z_OK)
            {
                free(*zstream);
                *zstream = NULL;
                return -1;
            }
            return outlen;
        }
    }
    return -1;
}
#endif
#ifdef HAVE_BZ2LIB
int xhttpd_bzip2(unsigned char **zstream, unsigned char *in, int inlen)
{
    unsigned char *out = NULL;
    bz_stream bz = {0};
    int outlen = 0;

    if(in && inlen > 0)
    {
        bz.bzalloc = NULL;
        bz.bzfree = NULL;
        bz.opaque = NULL;
        if(BZ2_bzCompressInit(&bz, 9, 0, 0) != BZ_OK)
        {
            return -1;
        }
        bz.next_in = (char *)in;
        bz.avail_in = inlen;
        bz.total_in_lo32 = 0;
        bz.total_in_hi32 = 0;
        outlen = (inlen * 1.1) + 12;
        if((*zstream = out = (unsigned char *)calloc(1, outlen)))
        {
            bz.next_out = (char *)out;
            bz.avail_out = outlen;
            bz.total_out_lo32 = 0;
            bz.total_out_hi32 = 0;
            if(BZ2_bzCompress(&bz, BZ_FINISH) != BZ_STREAM_END)
            {
                BZ2_bzCompressEnd(&bz);
                free(*zstream);
                *zstream = NULL;
                return -1;
            }
            if(bz.total_out_hi32)
            {
                free(*zstream);
                *zstream = NULL;
                return -1;
            }
            outlen = bz.total_out_lo32;
            if(BZ2_bzCompressEnd(&bz) != BZ_OK)
            {
                free(*zstream);
                *zstream = NULL;
                return -1;
            }
        }
    }
    return -1;
}
#endif

int xhttpd_resp_handler(CONN *conn, CB_DATA *packet)
{
    char *p = NULL,  buf[4096], *s = "sdklhafkllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllhflkdfklasdjfkldsakfldsalkfkasdfjksdjfkdasjfklasdjfklsdjfklsjdkfljdssssssssssssssssssssssssssssssssssssssssldkfjsakldjflkajsdfkljadkfjkldajfkljd";
    int x = 0, n = 0, keepalive = 0;

    if(conn && packet)
    {
        p = packet->data + packet->ndata; p = '\0';
        if(strcasestr(packet->data, "Keep-Alive")) keepalive = 1;
        x = strlen(s);
        if(keepalive)
        {
            n = sprintf(buf, "HTTP/1.0 200 OK\r\nConnection: Keep-Alive\r\nContent-Length:%d\r\n\r\n%s", x, s);conn->push_chunk(conn, buf, n); 
        }
        else
        {
            n = sprintf(buf, "HTTP/1.0 200 OK\r\nContent-Length:%d\r\n\r\n%s", x, s);conn->push_chunk(conn, buf, n); 

        }
        if(keepalive == 0) conn->over(conn); 
    }
    return 0;
}

/* httpd file compress */
int xhttpd_compress_handler(CONN *conn, HTTP_REQ *http_req, char *host, int is_need_compress, int mimeid,
        char *file, char *root, off_t from, off_t to, struct stat *st)
{
    char zfile[HTTP_PATH_MAX], zoldfile[HTTP_PATH_MAX], linkfile[HTTP_PATH_MAX], 
         buf[HTTP_BUF_SIZE], *encoding = NULL, *outfile = NULL, *p = NULL;
    int fd = 0, inlen = 0, zlen = 0, i = 0, id = 0, keepalive = 0, n = 0;
    unsigned char *block = NULL, *in = NULL, *zstream = NULL;
    off_t offset = 0, len = 0;
    struct stat zst = {0};

    if(is_need_compress)
    {
        if(httpd_compress)
        {
            for(i = 0; i < HTTP_ENCODING_NUM; i++)
            {
                if(is_need_compress & ((id = (1 << i))))
                {
                    encoding = (char *)http_encodings[i];
                    if(from == 0 && to == st->st_size)
                    {
                        sprintf(linkfile, "%s/%s%s.%s",  httpd_compress_cachedir,
                                host, root, encoding);
                    }
                    else
                    {
                        sprintf(linkfile, "%s/%s%s-%lld-%lld.%s", httpd_compress_cachedir, 
                                host, root, LL(from), LL(to), encoding);
                    }
                    sprintf(zfile, "%s.%lu", linkfile, UL(st->st_mtime));
                    if(access(zfile, F_OK) == 0)
                    {
                        stat(zfile, &zst);
                        outfile = zfile;
                        from = 0;
                        len = zst.st_size;
                        goto OVER;
                    }
                    else
                    {
                        if(access(linkfile, F_OK))
                        {
                            xhttpd_mkdir(linkfile, 0755);
                        }
                        else 
                        {
                            if(readlink(linkfile, zoldfile, (HTTP_PATH_MAX - 1)))
                                unlink(zoldfile);
                            unlink(linkfile);
                        }
                        goto COMPRESS;
                    }
                    break;
                }
            }
        }
COMPRESS:
        offset = (from/(off_t)HTTP_MMAP_MAX) * HTTP_MMAP_MAX;
        len = to - offset;
        if(len < HTTP_MMAP_MAX && (fd = open(file, O_RDONLY)) > 0)
        {
            if((block = (unsigned char *)mmap(NULL, len, PROT_READ, MAP_PRIVATE, fd, 0)))
            {
                in = block + (from%(off_t)HTTP_MMAP_MAX);
                inlen = to - from;

#ifdef HAVE_ZLIB
                if(is_need_compress & HTTP_ENCODING_DEFLATE)
                {
                    if((zlen = xhttpd_deflate(&zstream, in, inlen)) <= 0)
                        goto err;
                    encoding = "deflate";
                    //compressed |= HTTP_ENCODING_DEFLATE;
                }
                else if(is_need_compress & HTTP_ENCODING_GZIP)
                {
                    if((zlen = xhttpd_gzip(&zstream, in, inlen, 
                                    st->st_mtime)) <= 0) goto err;
                    encoding = "gzip";
                    //compressed |= HTTP_ENCODING_GZIP;

                }
                /*
                   else if(is_need_compress & HTTP_ENCODING_COMPRESS)
                   {
                   compressed |= HTTP_ENCODING_COMPRESS;
                   }
                   */
#endif		
#ifdef HAVE_BZ2LIB
                if(encoding == NULL && is_need_compress & HTTP_ENCODING_BZIP2)
                {
                    if((zlen = xhttpd_bzip2(&zstream, in, inlen)) <= 0) goto err;
                    encoding = "bzip2";
                    //compressed |= HTTP_ENCODING_BZIP2;
                }
#endif
                munmap(block, len);
                block = NULL;
            }
            close(fd);
            if(encoding == NULL) goto err;
            //write to cache file
            if(httpd_compress && zstream && zlen > 0)
            {
                if((fd = open(zfile, O_CREAT|O_WRONLY, 0644)) > 0)
                {
                    if(symlink(zfile, linkfile) != 0 || write(fd, zstream, zlen) <= 0 )
                    {
                        FATAL_LOGGER(default_logger, "symlink/write to %s failed, %s", 
                                linkfile, strerror(errno));
                    }
                    close(fd); 
                }
            }
        }
OVER:
        p = buf;
        if(from > 0)
        {
            p += sprintf(p, "HTTP/1.1 206 Partial Content\r\nAccept-Ranges: bytes\r\n"
                    "Content-Range: bytes %lld-%lld/%lld\r\n", 
                    LL(from), LL(to - 1), LL(st->st_size));
        }
        else
            p += sprintf(p, "HTTP/1.1 200 OK\r\nAccept-Ranges: bytes\r\n");
        if(mimeid >= 0)
            p += sprintf(p, "Content-Type: %s; charset=%s\r\n", http_mime_types[mimeid].s, http_default_charset);
        else
        {
            p += sprintf(p, "Content-Type: application/octet-stream; charset=%s\r\n",  http_default_charset);
        }
        if((n = http_req->headers[HEAD_GEN_CONNECTION]) > 0)
        {
            p += sprintf(p, "Connection: %s\r\n", http_req->hlines + n);
            if(strcasestr(http_req->hlines + n, "close") == NULL)
                keepalive = 1;
        }
        else
        {
            p += sprintf(p, "Connection: close\r\n");
        }
        p += sprintf(p, "Last-Modified:");
        p += GMTstrdate(st->st_mtime, p);
        p += sprintf(p, "%s", "\r\n");//date end
        if(zstream && zlen > 0) len = zlen;
        if(encoding) p += sprintf(p, "Content-Encoding: %s\r\n", encoding);
        p += sprintf(p, "Content-Length: %lld\r\n", LL(len));
        p += sprintf(p, "Date: ");p += GMTstrdate(time(NULL), p);p += sprintf(p, "\r\n");
        p += sprintf(p, "Server: xhttpd/%s\r\n\r\n", XHTTPD_VERSION);
        conn->push_chunk(conn, buf, (p - buf));
        if(zstream && zlen > 0)
        {
            conn->push_chunk(conn, zstream, zlen);
        }
        else
        {
            conn->push_file(conn, outfile, from, len);
        }
        if(zstream) free(zstream);
        if(!keepalive)conn->over(conn);
        else conn->set_timeout(conn, HTTPD_TIMEOUT);
        return 0;
    }
err:
    return -1;
}

/* exchange */
int xhttpd_exchange_handler(CONN *conn, CB_DATA *exchange)
{
    fprintf(stdout, "%s\n", exchange->data);
    return 0;
}

/* xhttpd bind proxy */
int xhttpd_bind_proxy(CONN *conn, char *host, int port) 
{
    CONN *new_conn = NULL;
    SESSION session = {0};
    struct hostent *hp = NULL;
    char *ip = NULL, cip[16];
    unsigned char *sip = NULL;
    SERVICE *service = NULL;

    if(conn && host && port > 0 && (hp = gethostbyname(host)) 
            && sprintf(cip, "%s", inet_ntoa(*((struct in_addr *)(hp->h_addr))))> 0
            && (service = (SERVICE *)conn->service))
    {
        if((ip = cip))
        {
            memset(&session, 0, sizeof(SESSION));
            session.packet_type = PACKET_PROXY;
            if(service->is_use_SSL) session.flags |= SB_USE_SSL;
            session.timeout = httpd_proxy_timeout;
            session.exchange_handler = &xhttpd_exchange_handler;
            if((new_conn = service->newproxy(service, conn, -1, -1, ip, port, &session)))
            {
                new_conn->start_cstate(new_conn);
                return 0;
            }
        }
    }
    return -1;
}

int xhttpd_proxy_handler(CONN *conn, HTTP_REQ *http_req)
{
    char buf[HTTP_BUF_SIZE], *host = NULL, *path = NULL, *s = NULL, *p = NULL;
    int n = 0, i = 0, port = conn->local_port;
    if(conn)
    {
        p = http_req->path;
        if(strncasecmp(p, "http://", 7) == 0)
        {
            p += 7;
            host = p;
            while(*p != '\0' && *p != ':' && *p != '/') ++p;
            if(*p == ':')
            {
                *p++ = '\0';
                port = atoi(p);
                while(*p >= '0' && *p <= '9') ++p;
                path = p;
            }
            else if(*p == '/') {*p++ = '\0'; path = p;}
            else if(*p == '\0') path = "";
            else path = p;
        }
        else
        {
            if((n = http_req->headers[HEAD_REQ_HOST]) > 0 )
            {
                path = p;
                host = (http_req->hlines + n);
            }
            else goto err_end;
        }
        if(path && *path == '/') ++path;
        if(path == NULL) path = "";
        if(http_req->reqid == HTTP_GET)
        {
            p = buf;
            p += sprintf(p, "GET /%s HTTP/1.1\r\n", path);
            if(host) p += sprintf(p, "Host: %s\r\n", host);
            for(i = 0; i < HTTP_HEADER_NUM; i++)
            {
                if(HEAD_REQ_HOST == i && host) continue;
                //if(HEAD_REQ_REFERER == i || HEAD_REQ_COOKIE == i) continue;
                if((n = http_req->headers[i]) > 0 && (s = (http_req->hlines + n)))
                {
                    p += sprintf(p, "%s %s\r\n", http_headers[i].e, s);
                }
            }
            p += sprintf(p, "%s", "\r\n");
            conn->push_exchange(conn, buf, (p - buf));
        }
        else if(http_req->reqid == HTTP_POST)
        {
            p = buf;
            p += sprintf(p, "POST /%s HTTP/1.1\r\n", path);
            if(host) p += sprintf(p, "Host: %s\r\n", host);
            for(i = 0; i < HTTP_HEADER_NUM; i++)
            {
                if(HEAD_REQ_HOST == i && host) continue;
                //HEAD_REQ_COOKIE
                if(HEAD_REQ_REFERER == i) continue;
                if((n = http_req->headers[i]) > 0 && (s = http_req->hlines + n))
                {
                    p += sprintf(p, "%s %s\r\n", http_headers[i].e, s);
                }
            }
            p += sprintf(p, "%s", "\r\n");
            fprintf(stdout, "host:%s port:%d\n", host, port);
            conn->push_exchange(conn, buf, (p - buf));
            fprintf(stdout, "%s", buf);
            conn->push_exchange(conn, conn->chunk.data, conn->chunk.ndata);
            fprintf(stdout, "%s\n", conn->chunk.data);
            /*
            if((n = http_req->headers[HEAD_ENT_CONTENT_LENGTH]) > 0
                    && (n = atol(http_req->hlines + n)) > 0)
            {
                conn->recv_chunk(conn, n);
            }
            */
        }
        else goto err_end;
        if(xhttpd_bind_proxy(conn, host, port) == -1) goto err_end;
        return 0;
    }
err_end:
    conn->push_chunk(conn, HTTP_BAD_REQUEST, strlen(HTTP_BAD_REQUEST));
    return -1;
}

int xhttpd_xpacket_handler(CONN *conn, CB_DATA *packet)
{
    if(conn && packet)
    {
        return xhttpd_resp_handler(conn, packet);
    }
    return -1;
}

int xhttpd_timeout_handler(CONN *conn, CB_DATA *packet, CB_DATA *cache, CB_DATA *chunk)
{
    if(conn)
    {
        //conn->over(conn);
    }
    return 0;
}
#define HTTPD_ACCESS_LOG(logger, conn, respid, host, http_req, agent, referer) REALLOG(logger, "%s host[%s] %s[%s] remote[%s:%d] agent[%s] referer[%s]", response_status[respid].e, host, http_methods[http_req.reqid].e, http_req.path, conn->remote_ip, conn->remote_port, agent, referer)

/* packet handler */
int xhttpd_packet_handler(CONN *conn, CB_DATA *packet)
{
    int i = 0, n = 0, found = 0, nmime = 0, mimeid = -1, is_need_compress = 0, keepalive = 0;
    char buf[HTTP_BUF_SIZE], file[HTTP_PATH_MAX], line[HTTP_PATH_MAX], *host = "",
         *mime = NULL, *home = NULL, *pp = NULL, *p = NULL, *end = NULL, *root = NULL, 
         *s = NULL, *outfile = NULL, *name = NULL, *encoding = NULL, *agent = "", *referer = "";
    off_t from = 0, to = 0, len = 0;
    HTTP_REQ http_req = {0} ;
    struct stat st = {0};
    DIR *newdir = NULL;
    void *logger = default_logger;

    if(conn && packet)
    {
        p = packet->data;end = packet->data + packet->ndata;
        //REALLOG(default_logger, "header:%s", p);
        //return xhttpd_index_view(conn, &http_req, httpd_home, "/");
        if(http_request_parse(p, end, &http_req, http_headers_map) == -1) goto err;
        //get vhost
        if((n = http_req.headers[HEAD_REQ_HOST]) > 0)
        {
            p = http_req.hlines + n;
            if(strncasecmp(p, "www.", 4) == 0) p += 4;
            host = p;
            while(*p != ':' && *p != '\0')
            {
                if(*p >= 'A' && *p <= 'Z') *p -= 'A' - 'a';
                ++p;
            }
            *p = '\0';
            n = p - host;
            if((i = mtrie_get(namemap, host, n) - 1) >= 0) 
            {
                logger = httpd_vhosts[i].logger;
                home = httpd_vhosts[i].home;
            }
        }
        if((n = http_req.headers[HEAD_REQ_USER_AGENT]) > 0)
        {
            agent = http_req.hlines + n;
        }
        if((n = http_req.headers[HEAD_REQ_REFERER]) > 0)
        {
            referer = http_req.hlines + n;
        }
        if(http_req.reqid == HTTP_GET)
        {
            if(home == NULL) home = httpd_home;
            if(home == NULL) goto err;
            p = file;
            p += sprintf(p, "%s", home);
            root = p;
            if(http_req.path[0] != '/')
                p += sprintf(p, "/%s", http_req.path);
            else
                p += sprintf(p, "%s", http_req.path);
            if((n = (p - file)) > 0 && stat(file, &st) == 0)
            {
                newdir = NULL;
                if(S_ISDIR(st.st_mode) || (newdir=opendir(file)))
                {
                    if(newdir){closedir(newdir);newdir = NULL;}
                    i = 0;
                    found = 0;
                    if(p > file && *(p-1) != '/') *p++ = '/';
                    //strcpy(p, "index.html");
                    //if(lstat(file, &st) == 0) found = 1;
                    //if(access(file, F_OK) == 0) found = 1;
                    while(i < nindexes && http_indexes[i])
                    {
                        pp = p;
                        pp += sprintf(pp, "%s", http_indexes[i]);
                        if(access(file, F_OK) == 0 && stat(file, &st) == 0)
                            //if(access(file, F_OK) == 0)
                        {
                            found = 1;
                            p = pp;
                            break;
                        }
                        ++i;
                    }
                    //index view
                    if(found == 0 && http_indexes_view && (*p = '\0') >= 0)
                    {
                        end = --p;

                        if(xhttpd_index_view(conn, &http_req, file, root) == 0) 
                        {
                            HTTPD_ACCESS_LOG(logger, conn, RESP_OK, host, http_req, agent, referer);
                            return 0; 
                        }
                        else 
                            goto err;
                    }
                }
                s = mime = line + HTTP_PATH_MAX - 1;
                *s = '\0';
                pp = --p ;
                while(pp > file && *pp != '.' && *pp != '/')
                {
                    if(*pp >= 'A' && *pp <= 'Z')
                    {
                        *--mime = *pp + ('a' - 'A');
                    }
                    else *--mime = *pp;
                    --pp;
                }
                //while( > file && *mime != '.')--mime;
                if(*pp == '.' && mime > line) nmime = s - mime;
                //no content
                if(st.st_size == 0)
                {
                    HTTPD_ACCESS_LOG(logger, conn, RESP_NOCONTENT, host, http_req, agent, referer);
                    return conn->push_chunk(conn, HTTP_NO_CONTENT, 
                            strlen(HTTP_NO_CONTENT));
                }
                //if not change
                else if((n = http_req.headers[HEAD_REQ_IF_MODIFIED_SINCE]) > 0
                        && str2time(http_req.hlines + n) == st.st_mtime)
                {
                    HTTPD_ACCESS_LOG(logger, conn, RESP_NOTMODIFIED, host, http_req, agent, referer);
                    return conn->push_chunk(conn, HTTP_NOT_MODIFIED, 
                            strlen(HTTP_NOT_MODIFIED));
                }
                else
                {
                    //range 
                    if((n = http_req.headers[HEAD_REQ_RANGE]) > 0)
                    {
                        p = http_req.hlines + n;
                        while(*p == 0x20 || *p == '\t')++p;
                        if(strncasecmp(p, "bytes=", 6) == 0) p += 6;
                        while(*p == 0x20)++p;
                        if(*p == '-')
                        {
                            ++p;
                            while(*p == 0x20)++p;
                            if(*p >= '0' && *p <= '9') to = (off_t)atoll(p) + 1;
                        }
                        else if(*p >= '0' && *p <= '9')
                        {
                            from = (off_t) atoll(p++);
                            while(*p != '-')++p;
                            ++p;
                            while(*p == 0x20)++p;
                            if(*p >= '0' && *p <= '9') to = (off_t)atoll(p) + 1;
                        }
                    }
                    if(to == 0) to = st.st_size;
                    len = to - from;
                    //mime 
                    if(mime && nmime > 0)
                    {
                        if((mimeid = mtrie_get(namemap, mime, nmime) - 1) >= 0
                                && (n = http_req.headers[HEAD_REQ_ACCEPT_ENCODING]) > 0 
                                && strstr(http_mime_types[mimeid].s, "text"))
                        {
                            p = http_req.hlines + n;
#ifdef HAVE_ZLIB
                            if(strstr(p, "deflate")) 
                                is_need_compress |= HTTP_ENCODING_DEFLATE;
                            if(strstr(p, "gzip")) 
                                is_need_compress |= HTTP_ENCODING_GZIP;	
                            //if(strstr(p, "compress")) is_need_compress |= HTTP_ENCODING_COMPRESS;
#endif
#ifdef HAVE_BZ2LIB
                            if(strstr(p, "bzip2")) 
                                is_need_compress |= HTTP_ENCODING_BZIP2;
#endif
                        }
                        if(mimeid < 0) 
                        {
                            end = root + 1;
                            while(*end != '\0')
                            {
                                if(*end  == '/') name = ++end;
                                else ++end;
                            }
                        }
                    }
                    if(is_need_compress > 0  && xhttpd_compress_handler(conn, 
                                &http_req, host, is_need_compress, mimeid, file, 
                                root, from, to, &st) == 0)
                    {
                        HTTPD_ACCESS_LOG(logger, conn, RESP_OK, host, http_req, agent, referer);
                        return 0;
                    }
                    else 
                        outfile = file;

                    p = buf;
                    if(from > 0)
                    {
                        HTTPD_ACCESS_LOG(logger, conn, RESP_PARTIALCONTENT, host, http_req, agent, referer);
                        p += sprintf(p, "HTTP/1.1 206 Partial Content\r\nAccept-Ranges: bytes\r\n"
                                "Content-Range: bytes %lld-%lld/%lld\r\n", 
                                LL(from), LL(to - 1), LL(st.st_size));
                    }
                    else
                    {
                        HTTPD_ACCESS_LOG(logger, conn, RESP_OK, host, http_req, agent, referer);
                        p += sprintf(p, "HTTP/1.1 200 OK\r\nAccept-Ranges: bytes\r\n");
                    }
                    if(mimeid >= 0)
                    {
                        p += sprintf(p, "Content-Type: %s; charset=%s\r\n", http_mime_types[mimeid].s, http_default_charset);
                    }
                    else if(nmime > 0)
                    {
                        p += sprintf(p, "Content-Type: application/octet-stream; charset=%s\r\n",  http_default_charset);
                    }
                    else
                    {
                        p += sprintf(p, "Content-Type: text/plain; charset=%s\r\n",  http_default_charset);
                    }
                    if((n = http_req.headers[HEAD_GEN_CONNECTION]) > 0)
                    {
                        p += sprintf(p, "Connection: %s\r\n", http_req.hlines + n);
                        if(strcasestr(http_req.hlines + n, "close") == NULL)
                            keepalive = 1;
                    }
                    else
                    {
                        p += sprintf(p, "Connection: close\r\n");
                    }
                    p += sprintf(p, "Last-Modified:");
                    p += GMTstrdate(st.st_mtime, p);
                    p += sprintf(p, "%s", "\r\n");//date end
                    if(encoding) p += sprintf(p, "Content-Encoding: %s\r\n", encoding);
                    if(name) 
                        p += sprintf(p, "Content-Disposition: attachment; filename=\"%s\"\r\n",name);
                    p += sprintf(p, "Date: ");p += GMTstrdate(time(NULL),p);p += sprintf(p,"\r\n");
                    p += sprintf(p, "Content-Length: %lld\r\n", LL(len));
                    p += sprintf(p, "Server: xhttpd/%s\r\n\r\n", XHTTPD_VERSION);
                    conn->push_chunk(conn, buf, p - buf);
                    conn->push_file(conn, outfile, from, len);
                    if(!keepalive) conn->over(conn);
                    else conn->set_timeout(conn, HTTPD_TIMEOUT);
                    return 0;
                }
            }
        }
        else if(http_req.reqid == HTTP_POST)
        {
            if((n = http_req.headers[HEAD_ENT_CONTENT_LENGTH]) > 0 
                    && (p = (http_req.hlines + n)) && (n = atoi(p)) > 0)
            {
                conn->save_cache(conn, &http_req, sizeof(HTTP_REQ));
                return conn->recv_chunk(conn, n);
            }
            return conn->push_chunk(conn, HTTP_NOT_FOUND, strlen(HTTP_NOT_FOUND));
        }
err:
        return conn->push_chunk(conn, HTTP_NOT_FOUND, strlen(HTTP_NOT_FOUND));
    }
    return -1;
}

/* data handler */
int xhttpd_data_handler(CONN *conn, CB_DATA *packet, CB_DATA *cache, CB_DATA *chunk)
{
    if(conn)
    {
        //REALLOG(default_logger, "data:%s", chunk->data);
        return xhttpd_proxy_handler(conn, (HTTP_REQ *)(cache->data));
        //return conn->push_chunk(conn, HTTP_NO_CONTENT, strlen(HTTP_NO_CONTENT));
    }
    return -1;
}

/* OOB handler */
int xhttpd_oob_handler(CONN *conn, CB_DATA *oob)
{
    if(conn && conn->push_chunk)
    {
        conn->push_chunk((CONN *)conn, ((CB_DATA *)oob)->data, oob->ndata);
        return oob->ndata;
    }
    return -1;
}

/* signal */
static void xhttpd_stop(int sig)
{
    switch (sig) 
    {
        case SIGINT:
        case SIGTERM:
            fprintf(stderr, "xhttpd server is interrupted by user.\n");
            if(sbase)sbase->stop(sbase);
            break;
        default:
            break;
    }
}

/* SIGPIPE */
/*
static void xhttpd_sigpipe(int sig)
{
    struct sigaction sa = {0};
    sa.sa_handler = SIG_IGN;
    sigaction(SIGPIPE, &sa,0); 
}
*/

/* Initialize from ini file */
int sbase_initialize(SBASE *sbase, char *conf)
{
    char *s = NULL, *p = NULL, *cert = NULL, *priv = NULL, path[HTTP_PATH_MAX];
    int n = 0, i = 0;

    if((dict = iniparser_new(conf)) == NULL)
    {
        fprintf(stderr, "Initializing conf:%s failed, %s\n", conf, strerror(errno));
        _exit(-1);
    }
    /* SBASE */
    sbase->nchilds = iniparser_getint(dict, "SBASE:nchilds", 0);
    sbase->connections_limit = iniparser_getint(dict, "SBASE:connections_limit", SB_CONN_MAX);
    sbase->usec_sleep = iniparser_getint(dict, "SBASE:usec_sleep", SB_USEC_SLEEP);
    sbase->set_log(sbase, iniparser_getstr(dict, "SBASE:logfile"));
    sbase->set_log_level(sbase, iniparser_getint(dict, "SBASE:log_level", 0));
    sbase->set_evlog(sbase, iniparser_getstr(dict, "SBASE:evlogfile"));
    sbase->set_evlog_level(sbase, iniparser_getint(dict, "SBASE:evlog_level", 0));
    setrlimiter("RLIMIT_NOFILE", RLIMIT_NOFILE, sbase->connections_limit);
    cert = iniparser_getstr(dict, "XHTTPD:cacert_file");
    priv = iniparser_getstr(dict, "XHTTPD:privkey_file");
    n = iniparser_getint(dict, "XHTTPD:SSL_port", 0);
    if(iniparser_getint(dict, "XHTTPD:is_use_SSL", 0) && n > 0 
        && (httpsd = service_init()))
    {
        httpsd->is_use_SSL = 1;
        httpsd->port = n;
        httpsd->cacert_file = cert;
        httpsd->privkey_file = priv;
    }
    else
    {
        fprintf(stderr, "initialize SSL[cacert:%s key:%s port:%d] failed, %s\n", cert, priv, n, strerror(errno));
        _exit(-1);
    }
    /* XHTTPD */
    if((httpd = service_init()) == NULL)
    {
        fprintf(stderr, "Initialize service failed, %s", strerror(errno));
        _exit(-1);
    }
    httpd->family = iniparser_getint(dict, "XHTTPD:inet_family", AF_INET);
    httpd->sock_type = iniparser_getint(dict, "XHTTPD:socket_type", SOCK_STREAM);
    httpd->ip = iniparser_getstr(dict, "XHTTPD:service_ip");
    httpd->port = iniparser_getint(dict, "XHTTPD:service_port", 80);
    httpd->working_mode = iniparser_getint(dict, "XHTTPD:working_mode", WORKING_THREAD);
    httpd->service_type = iniparser_getint(dict, "XHTTPD:service_type", S_SERVICE);
    httpd->service_name = iniparser_getstr(dict, "XHTTPD:service_name");
    httpd->nprocthreads = iniparser_getint(dict, "XHTTPD:nprocthreads", 1);
    httpd->ndaemons = iniparser_getint(dict, "XHTTPD:ndaemons", 0);
    httpd->niodaemons = iniparser_getint(dict, "XHTTPD:niodaemons", 2);
    httpd->use_cond_wait = iniparser_getint(dict, "XHTTPD:use_cond_wait", 1);
    if(iniparser_getint(dict, "XHTTPD:use_cpu_set", 0) > 0) httpd->flag |= SB_CPU_SET;
    if(iniparser_getint(dict, "XHTTPD:while_send", 0) > 0) httpd->flag |= SB_WHILE_SEND;
    if(iniparser_getint(dict, "XHTTPD:event_lock", 0) > 0) httpd->flag |= SB_EVENT_LOCK;
    if(iniparser_getint(dict, "XHTTPD:newconn_delay", 0) > 0) httpd->flag |= SB_NEWCONN_DELAY;
    if(iniparser_getint(dict, "XHTTPD:tcp_nodelay", 0) > 0) httpd->flag |= SB_TCP_NODELAY;
    if(iniparser_getint(dict, "XHTTPD:socket_linger", 0) > 0) httpd->flag |= SB_SO_LINGER;
    if(iniparser_getint(dict, "XHTTPD:log_thread", 0) > 0) httpd->flag |= SB_LOG_THREAD;
    if(iniparser_getint(dict, "XHTTPD:use_outdaemon", 0) > 0) httpd->flag |= SB_USE_OUTDAEMON;
    if(iniparser_getint(dict, "XHTTPD:use_evsig", 0) > 0) httpd->flag |= SB_USE_EVSIG;
    if(iniparser_getint(dict, "XHTTPD:use_cond", 0) > 0) httpd->flag |= SB_USE_COND;
    if((n = iniparser_getint(dict, "XHTTPD:sched_realtime", 0)) > 0) httpd->flag |= (n & (SB_SCHED_RR|SB_SCHED_FIFO));
    if((n = iniparser_getint(dict, "XHTTPD:io_sleep", 0)) > 0) httpd->flag |= ((SB_IO_NANOSLEEP|SB_IO_USLEEP|SB_IO_SELECT) & n);
    httpd->nworking_tosleep = iniparser_getint(dict, "XHTTPD:nworking_tosleep", SB_NWORKING_TOSLEEP);
    httpd->set_log(httpd, iniparser_getstr(dict, "XHTTPD:logfile"));
    httpd->set_log_level(httpd, iniparser_getint(dict, "XHTTPD:log_level", 0));
    httpd->session.packet_type=iniparser_getint(dict, "XHTTPD:packet_type",PACKET_DELIMITER);
    if((httpd->session.packet_delimiter = iniparser_getstr(dict, "XHTTPD:packet_delimiter")))
    {
        p = s = httpd->session.packet_delimiter;
        while(*p != 0 )
        {
            if(*p == '\\' && *(p+1) == 'n')
            {
                *s++ = '\n';
                p += 2;
            }
            else if (*p == '\\' && *(p+1) == 'r')
            {
                *s++ = '\r';
                p += 2;
            }
            else
                *s++ = *p++;
        }
        *s++ = 0;
        httpd->session.packet_delimiter_length = strlen(httpd->session.packet_delimiter);
    }
    httpd->session.buffer_size = iniparser_getint(dict, "XHTTPD:buffer_size", SB_BUF_SIZE);
    httpd->session.packet_reader = &xhttpd_packet_reader;
    httpd->session.packet_handler = &xhttpd_packet_handler;
    httpd->session.timeout_handler = &xhttpd_timeout_handler;
    httpd->session.data_handler = &xhttpd_data_handler;
    httpd->session.oob_handler = &xhttpd_oob_handler;
    //httpd->session.timeout = HTTPD_TIMEOUT;
    if(httpsd)
    {
        httpsd->family = iniparser_getint(dict, "XHTTPD:inet_family", AF_INET);
        httpsd->sock_type = iniparser_getint(dict, "XHTTPD:socket_type", SOCK_STREAM);
        httpsd->ip = iniparser_getstr(dict, "XHTTPD:service_ip");
        httpsd->working_mode = iniparser_getint(dict, "XHTTPD:working_mode", WORKING_THREAD);
        httpsd->service_type = iniparser_getint(dict, "XHTTPD:service_type", S_SERVICE);
        httpsd->service_name = iniparser_getstr(dict, "XHTTPD:service_name");
        httpsd->nprocthreads = iniparser_getint(dict, "XHTTPD:nprocthreads", 1);
        httpsd->ndaemons = iniparser_getint(dict, "XHTTPD:ndaemons", 0);
        httpsd->niodaemons = iniparser_getint(dict, "XHTTPD:niodaemons", 2);
        httpsd->use_cond_wait = iniparser_getint(dict, "XHTTPD:use_cond_wait", 1);
        httpsd->nworking_tosleep = iniparser_getint(dict, "XHTTPD:nworking_tosleep", SB_NWORKING_TOSLEEP);
        httpsd->set_log(httpsd, iniparser_getstr(dict, "XHTTPD:SSL_logfile"));
        httpsd->set_log_level(httpsd, iniparser_getint(dict, "XHTTPD:SSL_log_level", 0));
        httpsd->flag = httpd->flag;
        memcpy(&(httpsd->session), &(httpd->session), sizeof(SESSION));
        httpsd->session.ssl_servername_handler = xhttpd_SSL_hostname_callback;
    }
    //httpd home
    if((http_headers_map = http_headers_map_init()) == NULL)
    {
        fprintf(stderr, "Initialize http_headers_map failed,%s", strerror(errno));
        _exit(-1);
    }
    if((p = iniparser_getstr(dict, "XHTTPD:httpd_home")))
        httpd_home = p;
    http_indexes_view = iniparser_getint(dict, "XHTTPD:http_indexes_view", 1);
    if((p = iniparser_getstr(dict, "XHTTPD:httpd_index")))
    {
        memset(http_indexes, 0, sizeof(char *) * HTTP_INDEX_MAX);
        nindexes = 0;
        while(nindexes < HTTP_INDEX_MAX && *p != '\0')
        {
            while(*p == 0x20 || *p == '\t' || *p == ',' || *p == ';')++p;
            if(*p != '\0') 
            {
                http_indexes[nindexes] = p;
                while(*p != '\0' && *p != 0x20 && *p != '\t' 
                        && *p != ',' && *p != ';')++p;
                *p++ = '\0';
                //fprintf(stdout, "%s::%d %d[%s]\n", __FILE__, __LINE__, nindexes, http_indexes[nindexes]);
                ++nindexes;
            }else break;
        }
    }
    if((httpd_compress = iniparser_getint(dict, "XHTTPD:httpd_compress", 0)))
    {
        if((p =  iniparser_getstr(dict, "XHTTPD:httpd_compress_cachedir")))
            httpd_compress_cachedir =  p;
        if(access(httpd_compress_cachedir, F_OK) && xhttpd_mkdir(httpd_compress_cachedir, 0755)) 
        {
            fprintf(stderr, "create compress cache dir %s failed, %s\n", 
                    httpd_compress_cachedir, strerror(errno));
            return -1;
        }
    }
    if((p = iniparser_getstr(dict, "XHTTPD:access_log_dir")))
    {
        httpd_access_log_dir = p;
        sprintf(path, "%s/httpd_access.log", p);
        LOGGER_INIT(default_logger, path);
    }
    //name map
    if((namemap = mtrie_init()))
    {
        for(i = 0; i < HTTP_MIME_NUM; i++)
        {
            p = http_mime_types[i].e;
            n = http_mime_types[i].elen;
            mtrie_add(namemap, p, n, i+1);
        }
        if((p = iniparser_getstr(dict, "XHTTPD:httpd_vhosts")))
        {
            memset(httpd_vhosts, 0, sizeof(HTTP_VHOST) * HTTP_VHOST_MAX);
            nvhosts = 0;
            while(nvhosts < HTTP_VHOST_MAX && *p != '\0')
            {
                while(*p != '[') ++p;
                ++p;
                while(*p == 0x20 || *p == '\t' || *p == ',' || *p == ';')++p;
                httpd_vhosts[nvhosts].name = p;
                while(*p != ':' && *p != 0x20 && *p != '\t' && *p != '\0') ++p;
                *p = '\0';
                if((n = (p - httpd_vhosts[nvhosts].name)) > 0)
                {
                    mtrie_add(namemap, httpd_vhosts[nvhosts].name, n, nvhosts + 1);
                }
                ++p;
                while(*p == 0x20 || *p == '\t' || *p == ',' || *p == ';')++p;
                httpd_vhosts[nvhosts].home = p;
                while(*p != ':' && *p != 0x20 && *p != '\t' && *p != '\0') ++p;
                *p++ = '\0';
                sprintf(path, "%s/%s.access.log", httpd_access_log_dir, httpd_vhosts[nvhosts].name );
		        LOGGER_INIT(httpd_vhosts[nvhosts].logger, path);
                while(*p != '{' && *p != 0x20 && *p != '\t' && *p != '\0') ++p;
                while(*p == 0x20 || *p == '\t')++p;
                if(*p == '{')
                {
                    ++p;
                    while(*p == 0x20 || *p == '\t')++p;
                    cert = p;
                    while(*p != ',' && *p != 0x20 && *p != '\t' && *p != '\0') ++p;
                    *p++ = '\0';
                    while(*p == 0x20 || *p == '\t' || *p == ',')++p;
                    priv = p;
                    while(*p != '}' && *p != 0x20 && *p != '\t' && *p != '\0') ++p;
                    *p++ = '\0';
                    if(access(cert, F_OK) == 0 && access(priv, F_OK) == 0)
                    {
#ifdef HAVE_SSL
                        httpd_vhosts[nvhosts].s_ctx = SSL_CTX_new(SSLv23_server_method()); 
                        if(SSL_CTX_use_certificate_file(XSSL_CTX(httpd_vhosts[nvhosts].s_ctx), 
                                    cert, SSL_FILETYPE_PEM) <= 0)
                        {
                            ERR_print_errors_fp(stdout);
                            return -1;
                        }
                        if (SSL_CTX_use_PrivateKey_file(XSSL_CTX(httpd_vhosts[nvhosts].s_ctx),
                                    priv, SSL_FILETYPE_PEM) <= 0)
                        {
                            ERR_print_errors_fp(stdout);
                            return -1;
                        }
                        if (!SSL_CTX_check_private_key(XSSL_CTX(httpd_vhosts[nvhosts].s_ctx)))
                        {
                            ERR_print_errors_fp(stdout);
                            return -1;
                        }
                        //fprintf(stdout, "home:%s name:%s cert:%s priv:%s s_ctx:%p\n", httpd_vhosts[nvhosts].home, httpd_vhosts[nvhosts].name, cert, priv, httpd_vhosts[nvhosts].s_ctx);
#endif
                    }
                }
                while(*p != ']' && *p != 0x20 && *p != '\t' && *p != '\0') ++p;
                *p++ = '\0';
		        ++nvhosts;
            }
        }
    }
    //host map
    hostmap = mtrie_init();
    urlmap = mtrie_init();
    /* server */
    //fprintf(stdout, "Parsing for server...\n");
    if(httpsd) sbase->add_service(sbase, httpsd);
    return sbase->add_service(sbase, httpd);
    /*
       if(httpd->sock_type == SOCK_DGRAM 
       && (p = iniparser_getstr(dict, "XHTTPD:multicast")) && ret == 0)
       {
       ret = httpd->add_multicast(service, p);
       }
       return ret;
       */
}

int main(int argc, char **argv)
{
    struct passwd *user = NULL;
    char *conf = NULL,ch = 0;
    int is_daemon = 0, i = 0;
    pid_t pid;

    /* get configure file */
    while((ch = getopt(argc, argv, "c:d")) != (char)-1)
    {
        if(ch == 'c') conf = optarg;
        else if(ch == 'd') is_daemon = 1;
    }
    if(conf == NULL)
    {
        fprintf(stderr, "Usage:%s -d -c config_file\n", argv[0]);
        _exit(-1);
    }
    /* locale */
    setlocale(LC_ALL, "C");
    /* signal */
    signal(SIGTERM, &xhttpd_stop);
    signal(SIGINT,  &xhttpd_stop);
    signal(SIGHUP,  &xhttpd_stop);
    signal(SIGPIPE, SIG_IGN);
    signal(SIGCHLD, SIG_IGN);
    signal(SIGALRM, SIG_IGN);
    //daemon
    if(is_daemon)
    {
        pid = fork();
        switch (pid) {
            case -1:
                perror("fork()");
                exit(EXIT_FAILURE);
                break;
            case 0: //child
                if(setsid() == -1)
                    exit(EXIT_FAILURE);
                break;
            default://parent
                _exit(EXIT_SUCCESS);
                break;
        }
    }
    //setpriority(PRIO_PROCESS, getpid(), 19);
    if((sbase = sbase_init()) == NULL)
    {
        exit(EXIT_FAILURE);
        return -1;
    }
    fprintf(stdout, "Initializing from configure file:%s\n", conf);
    /* Initialize sbase */
    if(sbase_initialize(sbase, conf) != 0 )
    {
        fprintf(stderr, "Initialize from configure file failed\n");
        exit(EXIT_FAILURE);
        return -1;
    }
    //fprintf(stdout, "Initialized successed%d/%d\n", sizeof(CNGROUP), sizeof(SERVICE));
    if((user = getpwnam("xhttpd")) == NULL || setuid(user->pw_uid) ) 
    {
        fprintf(stderr, "setuid() for xhttpd failed, %s\r\n", strerror(errno));
        exit(EXIT_FAILURE);
    }
    fprintf(stdout, "Initialized successed\n");
    /*
    if(httpd->sock_type == SOCK_DGRAM 
            && (p = iniparser_getstr(dict, "XHTTPD:multicast")))
    {
        if(httpd->add_multicast(httpd, p) != 0)
        {
            fprintf(stderr, "add multicast:%s failed, %s", p, strerror(errno));
            exit(EXIT_FAILURE);
            return -1;
        }
        p = "224.1.1.168";
        if(httpd->add_multicast(httpd, p) != 0)
        {
            fprintf(stderr, "add multicast:%s failed, %s", p, strerror(errno));
            exit(EXIT_FAILURE);
            return -1;
        }

    }
    */
    //fprintf(stdout, "%s::%d sizeof(SERVICE):%u sizeof(SBASE):%u sizeof(PROCTHREAD):%u sizeof(CONN):%u sizeof(SESSION):%u sizeof(CNGROUP):%u sizeof(struct sockaddr_in):%u sizeof(MUTEX):%d\n", __FILE__, __LINE__, sizeof(SERVICE), sizeof(SBASE), sizeof(PROCTHREAD), sizeof(CONN), sizeof(SESSION), sizeof(CNGROUP), sizeof(struct sockaddr_in), sizeof(MUTEX));
    //fprintf(stdout, "sizeof(EVENT):%d sizeof(EVBASE):%d sizeof(MUTEX):%d sizeof(struct timeval):%d\n", sizeof(EVENT), sizeof(EVBASE), sizeof(MUTEX), sizeof(struct timeval));
    //fprintf(stdout, "sizeof(SERVICE):%d sizeof(CHUNK):%d sizeof(MESSAGE):%d sizeof(MUTEX):%d sizeof(CONN):%d sizeof(HTTP_REQ):%d sizeof(LOGGER):%d sizeof(struct timeval):%d sizeof(struct stat):%d sizeof(pthread_t):%d\n", sizeof(SERVICE), sizeof(CHUNK), sizeof(QMESSAGE), sizeof(MUTEX), sizeof(CONN), sizeof(HTTP_REQ), sizeof(LOGGER), sizeof(struct timeval), sizeof(struct stat), sizeof(pthread_mutex_t));
    sbase->running(sbase, 0);
    //sbase->running(sbase, 300000000);sbase->stop(sbase);
    sbase->clean(sbase);
    if(namemap) mtrie_clean(namemap);
    if(hostmap) mtrie_clean(hostmap);
    if(urlmap) mtrie_clean(urlmap);
    if(http_headers_map) http_headers_map_clean(http_headers_map);
    for(i = 0; i < nvhosts; i++)
    {
        LOGGER_CLEAN(httpd_vhosts[i].logger);
        httpd_vhosts[i].logger = NULL;
#ifdef HAVE_SSL
        SSL_CTX_free(httpd_vhosts[i].s_ctx);
#endif
    }
    LOGGER_CLEAN(default_logger);
    if(dict)iniparser_free(dict);
    return 0;
}
