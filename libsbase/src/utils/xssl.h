#ifndef _XSSL_H_
#define _XSSL_H_
#ifdef HAVE_SSL
#include <openssl/ssl.h>
#include <openssl/err.h>
#include <openssl/x509.h>
#include <openssl/rand.h>
#include <openssl/crypto.h>
#define XSSL(ptr) ((SSL *)ptr)
#define XSSL_CTX(ptr) ((SSL_CTX *)ptr)
#endif
#endif
