#ifndef _LOS_COAP_CORE_H
#define _LOS_COAP_CORE_H

const unsigned char payloadmarker = 0xff;

typedef struct _coap_header_t
{
	char ver:2;			// version, must be 0x1
	char t:2;  			// type  Indicates if this message is of type Confirmable (0), Non-confirmable (1), Acknowledgement (2), or Reset (3)
	
	char tkl:4;			// token length, Indicates the length of the variable-length Token field (0-8 bytes). Lengths 9-15 are
						//reserved, MUST NOT be sent, and MUST be processed as a message format error
						
	unsigned char code;	// split into a 3-bit class and a 5-bit detail documented as "c.dd" "c" is a digit from 0 to 7 "dd" are two digits from 00 to 31
						//The class can indicate a request (0), a success response (2), a client error response (4), or a server error response (5). 
						//(All other class values are reserved.) Code 0.00 indicates an Empty message
	
	unsigned char msgid[2]; // 16-bit unsigned integer in network byte order. Used to detect message duplication and to match messages of type
							// Acknowledgement/Reset to messages of type Confirmable/Nonconfirmable.
	
} coap_header_t;

typedef struct _coap_token_t 
{
	unsigned char *token;
} coap_token_t;

typedef struct _coap_option_t 
{
	unsigned int optionnum;
	unsigned int optvallen;
	unsigned char *value;
	struct _coap_option_t *next;
} coap_option_t;

typedef struct _coap_pkg_t
{
	coap_header_t head;
	coap_token_t *tok;
	coap_option_t *option;
	unsigned short optcnt;
	unsigned char payloadmarker;
	unsigned char *payload;
	unsigned int payloadlen;
}coap_pkg_t;


typedef struct _coap_pkg_list_t
{
	coap_pkg_t *pkg;
	struct _coap_pkg_list_t *next;	
}coap_pkg_list_t;


#endif
