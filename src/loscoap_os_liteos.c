#include "../include/los_coap.h"
#include "../include/coap_core.h"
#include "../include/los_coap_err.h"

#define WITH_LITEOS

#ifdef WITH_LITEOS

#include "los_lwip.h"
#include "los_config.h"
#include "los_memory.h"
#include "los_api_dynamic_mem.h"


#define G_LOS_COAP_SMALL_STRUCT_MAX 64
#define G_LOS_COAP_MEM_POOL_SIZE 2048
unsigned char g_los_coap_mempool[G_LOS_COAP_MEM_POOL_SIZE];
unsigned char g_los_token[4] = {0};

unsigned char *g_coap_mem = NULL;


int los_coap_lwip_send(void *handle, char *buf, int size);
int los_coap_lwip_read(void *handle, char *buf, int size);

struct udp_ops network_ops = 
{
    .network_read = los_coap_lwip_read,
    .network_send = los_coap_lwip_send
};

static unsigned int los_coap_get_random(void)
{
	unsigned int ret;
	LOS_TickCountGet();
	srand((unsigned)LOS_TickCountGet());
	ret = rand() % RAND_MAX;
	return ret;
}

int los_coap_generate_token(unsigned char *token)
{
	unsigned int ret;
	srand((unsigned)LOS_TickCountGet());
	ret = rand() % RAND_MAX;
    token[0] = (unsigned char)ret;
    token[1] = (unsigned char)(ret>>8);
    token[2] = (unsigned char)(ret>>16);
    token[3] = (unsigned char)(ret>>24);
	return 4;
}


int los_coap_stack_init(void)
{
	UINT32 uwRet;
	g_coap_mem = g_los_coap_mempool;
	uwRet = LOS_MemInit(g_coap_mem, G_LOS_COAP_MEM_POOL_SIZE);
    if (LOS_OK != uwRet) 
    {
        return -LOS_COAP_STATACK_INIT_FAILED;
    }
    
 	return 0;   
}

void *los_coap_malloc(int size)
{
    char *tmp = NULL;
    if (size <= 0)
    {
        return NULL;
    }
    tmp = (char *)LOS_MemAlloc(g_coap_mem, size);
    return (void *)tmp;
}

int los_coap_free(void *p)
{
    if (NULL == p)
	{
		return -LOS_COAP_PARAM_NULL;
	}

    LOS_MemFree(g_coap_mem, p);
    return 0;
}

static int los_coap_check_validip(char *ipaddr)
{
    int a = 0;
    int b = 0;
    int c = 0;
    int d = 0;
    int ret = 0;
    if(NULL == ipaddr)
    {
        return -LOS_COAP_PARAM_NULL;
    }
    ret = sscanf(ipaddr, "%d.%d.%d.%d", &a,&b,&c,&d);
    if (ret != 4)
    {
        return -1;
    }
    if ((a >= 0 && a <= 255)
        && (b >=0 && b <= 255)
        && (c >=0 && c <= 255)
        && (d >=0 && d <= 255))
    {
        return 0;
    }
    return -1;
}
void *los_coap_new_resource(char *ipaddr, unsigned short port)
{
    int ret = 0;
    struct lwip_udp_res_t *tmp = NULL;
    if (NULL == ipaddr)
    {
        return NULL;
    }
    ret = los_coap_check_validip(ipaddr);
    if (ret < 0)
    {
        return NULL;
    }
    tmp = (struct lwip_udp_res_t *)LOS_MemAlloc(g_coap_mem, sizeof(struct lwip_udp_res_t));
    if (NULL == tmp)
    {
        return NULL;
    }
    memset(tmp, 0, sizeof(struct lwip_udp_res_t));
    tmp->fd = socket(AF_INET, SOCK_DGRAM, 0);
    if (tmp->fd < 0)
    {
        LOS_MemFree(g_coap_mem, tmp);
        return NULL;
    }
    tmp->remoteAddr.sin_addr.s_addr = inet_addr((const char *)ipaddr);
    tmp->remoteAddr.sin_port = htons(port);
    tmp->remoteAddr.sin_family = AF_INET;
    return (void *)tmp;
}

static int los_coap_delete_resource(void *res)
{
    struct lwip_udp_res_t *tmp = NULL;
    if (NULL == res)
	{
		return -1;
	}
    tmp = (struct lwip_udp_res_t *)res;
    if (tmp->fd >= 0)
    {
        lwip_close(tmp->fd);
    }
    LOS_MemFree(g_coap_mem, tmp);
    return 0;
}

coap_context_t *los_coap_malloc_context(void *res)
{
	coap_context_t *tmp = NULL;
	if (NULL == res)
	{
		return NULL;
	}
	
	tmp = (coap_context_t *)LOS_MemAlloc(g_coap_mem, sizeof(coap_context_t));
	if (NULL == tmp)
	{
		return NULL;
	}
	
	// FIXED ME 
	tmp->udpio = res;
	
	tmp->sndbuf.buf = (unsigned char *)LOS_MemAlloc(g_coap_mem, LOSCOAP_CONSTRAINED_BUF_SIZE);
	if (NULL == tmp->sndbuf.buf)
	{
        LOS_MemFree(g_coap_mem, tmp);
		return NULL;
	}
	tmp->sndbuf.len = LOSCOAP_CONSTRAINED_BUF_SIZE;
	
	tmp->rcvbuf.buf = (unsigned char *)LOS_MemAlloc(g_coap_mem, LOSCOAP_CONSTRAINED_BUF_SIZE);
	if (NULL == tmp->rcvbuf.buf)
	{
        LOS_MemFree(g_coap_mem, tmp);
        LOS_MemFree(g_coap_mem, tmp->sndbuf.buf);
		return NULL;
	}
    
	tmp->rcvbuf.len = LOSCOAP_CONSTRAINED_BUF_SIZE;
	tmp->msgid = (unsigned short)los_coap_get_random();
    tmp->netops = &network_ops;
    
    tmp->response_handler = NULL;
	return tmp;	
}

int los_coap_free_context(coap_context_t *ctx)
{
	coap_context_t *tmp = ctx;
    
	if (NULL == ctx)
	{
		return -1;
	}
	if (NULL != tmp->udpio)
    {
        los_coap_delete_resource(tmp->udpio);
        tmp->udpio = NULL;
    }

    if (NULL != tmp->sndbuf.buf)
    {
        LOS_MemFree(g_coap_mem, tmp->sndbuf.buf);
        tmp->sndbuf.buf = NULL;
        tmp->sndbuf.len = 0;
    }
    if (NULL != tmp->rcvbuf.buf)
    {
        LOS_MemFree(g_coap_mem, tmp->rcvbuf.buf);
        tmp->rcvbuf.buf = NULL;
        tmp->rcvbuf.len = 0;
    }
    tmp->netops = NULL;
    tmp->response_handler = NULL;
    LOS_MemFree(g_coap_mem, ctx);
    
	return 0;	
}

int los_coap_lwip_send(void *handle, char *buf, int size)
{
    int n = 0;
    struct lwip_udp_res_t *res = NULL;
    if (NULL == handle || NULL == buf)
    {
        return -LOS_COAP_PARAM_NULL;
    }
    res = (struct lwip_udp_res_t *)handle;
    if (res->fd < 0)
    {
        return -LOS_COAP_SOCKET_HANDLER_ERR;
    }
	n = sendto(res->fd,
			buf,
			size,
			0, 
			(struct sockaddr *)&res->remoteAddr,
			sizeof(struct sockaddr_in));
    return n;
}

int los_coap_lwip_read(void *handle, char *buf, int size)
{
    int n = 0;
    struct sockaddr_in fromAddr;
    socklen_t fromLen;
    struct lwip_udp_res_t *res = NULL;
    if (NULL == handle || NULL == buf)
    {
        return -LOS_COAP_PARAM_NULL;
    }
    res = (struct lwip_udp_res_t *)handle;
    if (res->fd < 0)
    {
        return -LOS_COAP_SOCKET_HANDLER_ERR;
    }
    
    memset(&fromAddr,0, sizeof(fromAddr));  
    fromAddr.sin_family = AF_INET;  
    fromAddr.sin_addr.s_addr = htonl(INADDR_ANY);  
    fromAddr.sin_port = res->remoteAddr.sin_port;  
    fromLen=sizeof(fromAddr);
    
    n = recvfrom( res->fd, 
                buf, size, 
                0, 
                (struct sockaddr *)&fromAddr, 
                &fromLen );
    return n;
}


#endif /* WITH_LITEOS */

