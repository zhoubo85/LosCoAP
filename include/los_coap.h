#ifndef _LOS_COAP_H
#define _LOS_COAP_H

#include "coap_core.h"

int los_coap_stack_init(void);

void *los_coap_malloc(int size);
int los_coap_free(void *p);
/**
 * use server ip and port to create coap_context_t resources
 */
void *los_coap_new_resource(char *ipaddr, unsigned short port);

/**
 * Create a new coap_context_t object that will hold the CoAP resources.
 */
coap_context_t *los_coap_malloc_context(void *res);
int los_coap_free_context(coap_context_t *ctx);

coap_option_t * los_coap_add_option_to_list(coap_option_t *head, 
								unsigned short option, 
								char *value, int len);

int los_coap_add_token(coap_msg_t *msg, char *tok, int tklen);

coap_msg_t *los_coap_new_msg(coap_context_t *ctx,
								unsigned char msgtype, 
								unsigned char code, 
								coap_option_t *optlist, 
								unsigned char *paylaod, 
								int payloadlen);
								
int los_coap_register_handler(coap_context_t *ctx, msghandler func);
int los_coap_read(coap_context_t *ctx);
int los_coap_send(coap_context_t *ctx, coap_msg_t *msg);




#endif
