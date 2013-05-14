#include <stdio.h>
#include <unistd.h>
#include <stdlib.h>
#include <string.h>
#include "xtree64.h"
#define LL(xxxx) ((long long int) xxxx)
int xtree64_add(XTREE64 *xtree64, int64_t key, int64_t data, int64_t *old)
{
    XTNODE64 *xp = NULL, *node = NULL;
    int ret = -1;

    if(xtree64)
    {
        if((xp = xtree64->root) && xtree64->total > 0 && xtree64->kmin && xtree64->kmax)
        {
            //fprintf(stdout, "%s::%d key:%d min:%d max:%d total:%d\n", __FILE__, __LINE__, key, xtree64->kmin->key, xtree64->kmax->key, xtree64->total);
            if(key == xtree64->kmin->key)
            {
                *old = xtree64->kmin->data;
                ret = 1;
            }
            else if(key == xtree64->kmax->key)
            {
                *old = xtree64->kmax->data;
                ret = 1;
            }
            else if(key < xtree64->kmin->key)
            {
                XTNODE64_POP(xtree64, node);
                node->key = key;
                node->data = data;
                xp = xtree64->kmin;
                node->parent = xp;
                node->left = node->right = NULL;
                xp->left = node;
                /*
                if(xp->right == NULL)
                {
                    if((node->parent = xp->parent))
                        node->parent->left = node;
                    else 
                        xtree64->root = node;
                    xp->parent = node;
                    node->right = xp;
                    node->left = NULL;
                }
                else
                {
                    node->left = node->right = NULL;
                    node->parent = xp;
                    xp->left = node;
                }
                */
                xtree64->kmin = node;
                ++(xtree64->total);
                ret = 0;
            }
            else if(key > xtree64->kmax->key)
            {
                XTNODE64_POP(xtree64, node);
                node->key = key;
                node->data = data;
                xp = xtree64->kmax;
                node->parent = xp;
                node->left = node->right = NULL;
                xp->right = node;
                /*
                if(xp->left == NULL)
                {
                    if((node->parent = xp->parent))
                        node->parent->right = node;
                    else
                        xtree64->root = node;
                    xp->parent = node;
                    node->left = xp;
                    node->right = NULL;
                }
                else
                {
                    node->left = node->right = NULL;
                    node->parent = xp;
                    xp->right = node;
                }
                */
                xtree64->kmax = node;
                ++(xtree64->total);
                ret = 0;
                //if(xtree64->kmin == NULL){fprintf(stdout, "%s::%d total:%d root:%p\n", __FILE__, __LINE__, xtree64->total, xtree64->root);_exit(-1);}
            }
            else
            {
                do
                {
                    if(key > xp->key) 
                    {
                        if(xp->right) xp = xp->right;
                        else
                        {
                            XTNODE64_POP(xtree64, node);
                            node->parent = xp;
                            xp->right = node;
                            node->key = key;
                            node->data = data;
                            node->left = NULL;
                            node->right = NULL;
                            ++(xtree64->total);
                            ret = 0;
                            break;
                        }
                    }
                    else 
                    {
                        if(xp->left) xp = xp->left;
                        else
                        {
                            XTNODE64_POP(xtree64, node);
                            xp->left = node;
                            node->parent = xp;
                            node->key = key;
                            node->data = data;
                            node->left = NULL;
                            node->right = NULL;
                            ++(xtree64->total);
                            ret = 0;
                            break;
                        }
                    }
                }while(xp);
            }
            //if(xtree64->kmin == NULL){fprintf(stdout, "%s::%d total:%d root:%p\n", __FILE__, __LINE__, xtree64->total, xtree64->root);_exit(-1);}
        }
        else
        {
            XTNODE64_POP(xtree64, node);
            node->key = key;
            node->data = data;
            xtree64->root = xtree64->kmin = xtree64->kmax = node;
            node->parent = NULL;
            node->left = NULL;
            node->right = NULL;
            ++(xtree64->total);
            ret = 0;
        }
    }
    return ret;
}//while(0)

int xtree64_push(XTREE64 *xtree64, int64_t key, int64_t data)
{
    XTNODE64 *xp = NULL, *node = NULL;
    int ret = -1;

    if(xtree64)
    {
        if((xp = xtree64->root) && xtree64->total > 0 && xtree64->kmin && xtree64->kmax)
        {
            //fprintf(stdout, "%s::%d key:%d min:%d max:%d total:%d\n", __FILE__, __LINE__, key, xtree64->kmin->key, xtree64->kmax->key, xtree64->total);
            if(key <= xtree64->kmin->key)
            {
                XTNODE64_POP(xtree64, node);
                node->key = key;
                node->data = data;
                xp = xtree64->kmin;
                node->parent = xp;
                node->left = node->right = NULL;
                xp->left = node;
                /*
                if(xp->right == NULL)
                {
                    if((node->parent = xp->parent))
                        node->parent->left = node;
                    else 
                        xtree64->root = node;
                    xp->parent = node;
                    node->right = xp;
                    node->left = NULL;
                }
                else
                {
                    node->left = node->right = NULL;
                    node->parent = xp;
                    xp->left = node;
                }
                */
                xtree64->kmin = node;
                ++(xtree64->total);
                ret = 0;
            }
            else if(key >= xtree64->kmax->key)
            {
                XTNODE64_POP(xtree64, node);
                node->key = key;
                node->data = data;
                xp = xtree64->kmax;
                node->parent = xp;
                node->left = node->right = NULL;
                xp->right = node;
                /*
                if(xp->left == NULL)
                {
                    if((node->parent = xp->parent))
                        node->parent->right = node;
                    else
                        xtree64->root = node;
                    xp->parent = node;
                    node->left = xp;
                    node->right = NULL;
                }
                else
                {
                    node->left = node->right = NULL;
                    node->parent = xp;
                    xp->right = node;
                }
                */
                xtree64->kmax = node;
                ++(xtree64->total);
                ret = 0;
                //if(xtree64->kmin == NULL){fprintf(stdout, "%s::%d total:%d root:%p\n", __FILE__, __LINE__, xtree64->total, xtree64->root);_exit(-1);}
            }
            else
            {
                do
                {
                    if(key > xp->key) 
                    {
                        if(xp->right) xp = xp->right;
                        else
                        {
                            XTNODE64_POP(xtree64, node);
                            node->parent = xp;
                            xp->right = node;
                            node->key = key;
                            node->data = data;
                            node->left = NULL;
                            node->right = NULL;
                            ++(xtree64->total);
                            ret = 0;
                            break;
                        }
                    }
                    else 
                    {
                        if(xp->left) xp = xp->left;
                        else
                        {
                            XTNODE64_POP(xtree64, node);
                            xp->left = node;
                            node->parent = xp;
                            node->key = key;
                            node->data = data;
                            node->left = NULL;
                            node->right = NULL;
                            ++(xtree64->total);
                            ret = 0;
                            break;
                        }
                    }
                }while(xp);
            }
            //if(xtree64->kmin == NULL){fprintf(stdout, "%s::%d total:%d root:%p\n", __FILE__, __LINE__, xtree64->total, xtree64->root);_exit(-1);}
        }
        else
        {
            XTNODE64_POP(xtree64, node);
            node->key = key;
            node->data = data;
            xtree64->root = xtree64->kmin = xtree64->kmax = node;
            node->parent = NULL;
            node->left = NULL;
            node->right = NULL;
            ++(xtree64->total);
            ret = 0;
        }
    }
    return ret;
}//while(0)


/* pop min key */
int xtree64_pop_min(XTREE64 *xtree64, int64_t *key, int64_t *data)
{
    XTNODE64 *xp = NULL, *node = NULL;
    int ret = -1;

    if(xtree64)
    {
        if((xp = xtree64->kmin))
        {
            if(key) *key = xp->key;
            if(data) *data = xp->data;
            if((node = xp->right))
            {
                if((node->parent = xp->parent)) 
                    xp->parent->left = node;
                else 
                    xtree64->root = node;
                while(node->left) node = node->left;
                xtree64->kmin = node;
                XTNODE64_PUSH(xtree64, xp);
            }
            else
            {
                xtree64->kmin = xp->parent;
                if(xp->parent) xp->parent->left = NULL;
                XTNODE64_PUSH(xtree64, xp);
            }
            if(--(xtree64->total) == 0)
                xtree64->root = xtree64->kmin = xtree64->kmax = NULL;
            ret = 0;
        }
    }
    return ret;
}

/* pop max key */
int xtree64_pop_max(XTREE64 *xtree64, int64_t *key, int64_t *data)
{
    XTNODE64 *xp = NULL, *node = NULL;
    int ret = -1;

    if(xtree64)
    {
        if((xp = xtree64->kmax))
        {
            if(key ) *key = xp->key;
            if(data) *data = xp->data;
            if((node = xp->left))
            {
                if((node->parent = xp->parent)) 
                    xp->parent->right = node;
                else 
                    xtree64->root = node;
                while(node->right) node = node->right;
                xtree64->kmax = node;
                XTNODE64_PUSH(xtree64, xp);
            }
            else
            {
                xtree64->kmax = xp->parent;
                if(xp->parent) xp->parent->right = NULL;
                XTNODE64_PUSH(xtree64, xp);
            }
            if(--(xtree64->total) == 0)
                xtree64->root = xtree64->kmin = xtree64->kmax = NULL;
            ret = 0;
        }
    }
    return ret;
}

void xtree64_reset(XTREE64 *xtree64)
{
    int64_t key = 0, data = 0;

    if(xtree64 && xtree64->total > 0 && xtree64->root &&  xtree64->kmin && xtree64->kmax)
    {
        while(xtree64_pop_min(xtree64, &key, &data) == 0);
        xtree64->root = xtree64->kmin = xtree64->kmax = NULL;
    }
    return ;
}

void xtree64_clean(XTREE64 *xtree64)
{
    int i = 0;

    if(xtree64)
    {
        xtree64_reset(xtree64);
        for(i = 0; i <  xtree64->nlines; i++)
        {
            free(xtree64->lines[i]);
        }
        free(xtree64);
    }
    return ;
}

XTREE64 *xtree64_init()
{
    XTREE64 *xtree64 = NULL;
    XTNODE64 *tmp = NULL;
    int i = 0;

    if((xtree64 = (XTREE64 *)calloc(1, sizeof(XTREE64))))
    {
        for(i = 0; i < XTRNODE64_LINE_NUM; i++)
        {
            tmp = &(xtree64->init[i]);
            XTNODE64_PUSH(xtree64, tmp);
        }
    }
    return xtree64;
}

#ifdef _DEBUG_XTREE64
int main()
{
    int64_t key = 0, data = 0, last = 0, old = 0;
    int i = 0, x = 0, count = 500000;
    XTREE64 *xtree64 = NULL;
    
    if((xtree64 = xtree64_init()))
    {
        for(i = 0; i < count; i++)
        {
            key = (int64_t)(rand()%count);
            data = (int64_t)i;
            if(xtree64_add(xtree64, key, data, &old) == 1)
            {
                fprintf(stdout, "%s::%d key:%lld old:%lld\n", __FILE__, __LINE__, LL(key), LL(old));
                ++x;
            }
            else
            {
                //fprintf(stdout, "%s::%d %d:%d\n", __FILE__, __LINE__, key, i);
            }
        }
        fprintf(stdout, "%s::%d min:%lld max:%lld count:%d repeat:%d\n", __FILE__, __LINE__, LL(xtree64->kmin->key), LL(xtree64->kmax->key), xtree64->total, x);
        i = 0;
        while(xtree64_pop_min(xtree64, &key, &data) == 0)
        {
            if(key < last)
            {
                fprintf(stdout, "%s::%d i:%d %lld:%lld last:%d\n", __FILE__, __LINE__, i, LL(key), LL(data), last);
                _exit(-1);
            }
            i++;
            last = key;
        }
        xtree64_reset(xtree64);
        //push 
        for(i = 0; i < count; i++)
        {
            key = (int64_t) i % count;
            data = (int64_t) i;
            xtree64_push(xtree64, key, data);
        }
        fprintf(stdout, "%s::%d min:%lld max:%lld count:%d\n", __FILE__, __LINE__, LL(xtree64->kmin->key), LL(xtree64->kmax->key), xtree64->total);
        i = 0;
        last = 0;
        while(xtree64_pop_min(xtree64, &key, &data) == 0)
        {
            if(key < last)
            {
                fprintf(stdout, "%s::%d i:%d %lld:%lld last:%d\n", __FILE__, __LINE__, i, LL(key), LL(data), last);
                _exit(-1);
            }
            i++;
            last = key;
        }
        xtree64_clean(xtree64);
    }
    return 0; 
}
//gcc -o xtr64 xtree64.c -D_DEBUG_XTREE64 &&  ./xtr64
#endif
