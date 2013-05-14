#ifndef _XTREE64_H_
#define _XTREE64_H_
typedef struct _XTNODE64
{
    int64_t key;
    int64_t data;
    struct _XTNODE64 *left;
    struct _XTNODE64 *right;
    struct _XTNODE64 *parent;
}XTNODE64;
#define XTRNODE64_LINE_NUM    2048
#define XTRNODE64_LINE_MAX    1024 
#define XTRNODE64_INCRE_NUM   2048
typedef struct _XTREE64
{
    int total;
    int bits;
    int x;
    int nlines;
    XTNODE64 *kmax;
    XTNODE64 *kmin;
    XTNODE64 *xnode;
    XTNODE64 *root;
    XTNODE64 *tmp;
    XTNODE64 *list;
    XTNODE64 *lines[XTRNODE64_LINE_MAX];
    XTNODE64 init[XTRNODE64_LINE_NUM];
}XTREE64;
#define XTNODE64_PUSH(xtree64, xtnode)                                                      \
do                                                                                          \
{                                                                                           \
    if((xtnode->parent = xtree64->list))                                                    \
        xtree64->list = xtnode;                                                             \
    else                                                                                    \
    {                                                                                       \
        xtree64->list = xtnode;                                                             \
        xtnode->parent = NULL;                                                              \
    }                                                                                       \
}while(0)
#define XTNODE64_POP(xtree64, xtnode)                                                           \
do                                                                                              \
{                                                                                               \
    if((xtnode = xtree64->list))                                                                \
    {                                                                                           \
        xtree64->list = xtnode->parent;                                                         \
    }                                                                                           \
    else                                                                                        \
    {                                                                                           \
        if(xtree64->nlines < XTRNODE64_LINE_MAX && (xtnode = xtree64->lines[xtree64->nlines++]  \
                = (XTNODE64 *)calloc(XTRNODE64_LINE_NUM, sizeof(XTNODE64))))                    \
        {                                                                                       \
            xtree64->x = XTRNODE64_LINE_NUM;                                                    \
            while(xtree64->x > 1)                                                               \
            {                                                                                   \
                xtree64->tmp = &(xtnode[--(xtree64->x)]);                                       \
                XTNODE64_PUSH(xtree64, xtree64->tmp);                                           \
            }                                                                                   \
        }                                                                                       \
    }                                                                                           \
}while(0)
#define XTR64(x) ((XTREE64 *)x)
#define XTREE64_MAXK(x)  XTR64(x)->kmax->key
#define XTREE64_MINK(x)  XTR64(x)->kmin->key
#define XTREE64_TOTAL(x) XTR64(x)->total
XTREE64 *xtree64_init();
int xtree64_add(XTREE64 *xtree64, int64_t key, int64_t data, int64_t *old);
int xtree64_push(XTREE64 *xtree64, int64_t key, int64_t data);
int xtree64_set_min(int64_t key, int64_t data);
int xtree64_set_max(int64_t key, int64_t data);
int xtree64_pop_max(XTREE64 *xtree64, int64_t *key, int64_t *data);
int xtree64_pop_min(XTREE64 *xtree64, int64_t *key, int64_t *data);
void xtree64_reset(XTREE64 *xtree64);
void xtree64_clean(XTREE64 *xtree64);
#endif
