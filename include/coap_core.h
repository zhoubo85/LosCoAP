#ifndef _LOS_COAP_CORE_H
#define _LOS_COAP_CORE_H


#define LOSCOAP_CONSTRAINED_BUF_SIZE 512




/* CoAP message types */

#define COAP_MESSAGE_CON       0 /* confirmable message (requires ACK/RST) */
#define COAP_MESSAGE_NON       1 /* non-confirmable message (one-shot message) */
#define COAP_MESSAGE_ACK       2 /* used to acknowledge confirmable messages */
#define COAP_MESSAGE_RST       3 /* indicates error in received messages */

/* CoAP request methods */

#define COAP_REQUEST_GET       1
#define COAP_REQUEST_POST      2
#define COAP_REQUEST_PUT       3
#define COAP_REQUEST_DELETE    4

/* CoAP option types (be sure to update check_critical when adding options */

#define COAP_OPTION_IF_MATCH        1 /* C, opaque, 0-8 B, (none) */
#define COAP_OPTION_URI_HOST        3 /* C, String, 1-255 B, destination address */
#define COAP_OPTION_ETAG            4 /* E, opaque, 1-8 B, (none) */
#define COAP_OPTION_IF_NONE_MATCH   5 /* empty, 0 B, (none) */
#define COAP_OPTION_URI_PORT        7 /* C, uint, 0-2 B, destination port */
#define COAP_OPTION_LOCATION_PATH   8 /* E, String, 0-255 B, - */
#define COAP_OPTION_URI_PATH       11 /* C, String, 0-255 B, (none) */
#define COAP_OPTION_CONTENT_FORMAT 12 /* E, uint, 0-2 B, (none) */
#define COAP_OPTION_CONTENT_TYPE COAP_OPTION_CONTENT_FORMAT
#define COAP_OPTION_MAXAGE         14 /* E, uint, 0--4 B, 60 Seconds */
#define COAP_OPTION_URI_QUERY      15 /* C, String, 1-255 B, (none) */
#define COAP_OPTION_ACCEPT         17 /* C, uint,   0-2 B, (none) */
#define COAP_OPTION_LOCATION_QUERY 20 /* E, String,   0-255 B, (none) */
#define COAP_OPTION_PROXY_URI      35 /* C, String, 1-1034 B, (none) */
#define COAP_OPTION_PROXY_SCHEME   39 /* C, String, 1-255 B, (none) */
#define COAP_OPTION_SIZE1          60 /* E, uint, 0-4 B, (none) */

/* option types from RFC 7641 */
#define COAP_OPTION_OBSERVE         6 /* E, empty/uint, 0 B/0-3 B, (none) */
#define COAP_OPTION_SUBSCRIPTION  COAP_OPTION_OBSERVE

/* selected option types from RFC 7959 */
#define COAP_OPTION_BLOCK2         23 /* C, uint, 0--3 B, (none) */
#define COAP_OPTION_BLOCK1         27 /* C, uint, 0--3 B, (none) */

/* selected option types from RFC 7967 */
#define COAP_OPTION_NORESPONSE    258 /* N, uint, 0--1 B, 0 */

#define COAP_MAX_OPT            65535 /**< the highest option number we know */


#define COAP_MSG_IS_EMPTY(MSG)    ((MSG)->head.code == 0)
#define COAP_MSG_IS_REQUEST(MSG)  (!COAP_MSG_IS_EMPTY(MSG) \
                                       && ((MSG)->head.code < 32))
#define COAP_MSG_IS_RESPONSE(MSG) ((MSG)->head.code >= 64)

#define COAP_RESP_CODE(N) (((N)/100 << 5) | (N)%100)

#define LOS_COAP_RESP_200      COAP_RESP_CODE(200)  /* 2.00 OK */
#define LOS_COAP_RESP_201      COAP_RESP_CODE(201)  /* 2.01 Created */
#define LOS_COAP_RESP_304      COAP_RESP_CODE(203)  /* 2.03 Valid */
#define LOS_COAP_RESP_400      COAP_RESP_CODE(400)  /* 4.00 Bad Request */
#define LOS_COAP_RESP_404      COAP_RESP_CODE(404)  /* 4.04 Not Found */
#define LOS_COAP_RESP_405      COAP_RESP_CODE(405)  /* 4.05 Method Not Allowed */
#define LOS_COAP_RESP_415      COAP_RESP_CODE(415)  /* 4.15 Unsupported Media Type */
#define LOS_COAP_RESP_500      COAP_RESP_CODE(500)  /* 5.00 Internal Server Error */
#define LOS_COAP_RESP_501      COAP_RESP_CODE(501)  /* 5.01 Not Implemented */
#define LOS_COAP_RESP_503      COAP_RESP_CODE(503)  /* 5.03 Service Unavailable */
#define LOS_COAP_RESP_504      COAP_RESP_CODE(504)  /* 5.04 Gateway Timeout */


#define COAP_TOKEN_LEN_MAX 8
#define COAP_PAYLOAD_MARKER 0xFF
//const unsigned char payloadmarker = 0xff;




typedef struct _coap_header_t
{
	unsigned char ver;			// version, must be 0x1
	unsigned char t;  			// type  Indicates if this message is of type Confirmable (0), Non-confirmable (1), Acknowledgement (2), or Reset (3)
	
	unsigned char tkl;			// token length, Indicates the length of the variable-length Token field (0-8 bytes). Lengths 9-15 are
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
	unsigned char tklen;//token length
} coap_token_t;

typedef struct _coap_option_t 
{
	unsigned short optnum;// option number
	unsigned short optlen;// option length
	unsigned char *value; // option valude
	struct _coap_option_t *next;
} coap_option_t;

typedef struct _coap_msg_t
{
	coap_header_t head;
	coap_token_t *tok;
	coap_option_t *option;
	unsigned short optcnt;
	unsigned char payloadmarker;
	unsigned char *payload;
	unsigned int payloadlen;
}coap_msg_t;

typedef struct _coap_rwbuf_t
{
	unsigned char *buf;
	int len;	
}coap_rwbuf_t;

#define LOS_MAX_SEGMENTS 2


typedef int (*sendfunc)(void *handle, char *buf, int size);
typedef int (*readfunc)(void *handle, char *buf, int size);

typedef int (*reshandler)(coap_msg_t *rcvmsg, coap_msg_t *outmsg);
typedef struct
{
    int count;
    char *elems[LOS_MAX_SEGMENTS];
} coap_res_path_t;
typedef struct
{
    unsigned char method;               /* (i.e. POST, PUT or GET) */
    reshandler handler;         /* callback function which handles this 
                                         * type of endpoint (and calls 
                                         * coap_make_response() at some point) */
    const coap_res_path_t *path;   /* path towards a resource (i.e. foo/bar/) */ 
    const char *core_attr;              /* the 'ct' attribute, as defined in RFC7252, section 7.2.1.:
                                         * "The Content-Format code "ct" attribute 
                                         * provides a hint about the 
                                         * Content-Formats this resource returns." 
                                         * (Section 12.3. lists possible ct values.) */
} coap_res_t;
struct udp_ops
{
	readfunc network_read;
	sendfunc network_send;
};

typedef struct _coap_send_queue_t
{
    coap_msg_t *msg;
    struct _coap_send_queue_t *next;
}send_queue_t;

struct _coap_context_t;
typedef int (*msghandler)(struct _coap_context_t *ctx, coap_msg_t *msg);
typedef struct _coap_context_t
{
	void *udpio;//  this is used to save remote server info , like address ¡¢ port ¡¢ socket fd etc...
	unsigned short msgid;//The last message id that was used is stored in this field, fist value usually a random value
	coap_rwbuf_t sndbuf;// to give real buf to store input package and output package data
	coap_rwbuf_t rcvbuf;// to give real buf to store input package and output package data
	struct udp_ops *netops;
	msghandler response_handler;//message deal callback function 
    send_queue_t *sndque;
    coap_res_t *res;
}coap_context_t;


typedef struct _coap_msg_list_t
{
	coap_msg_t *pkg;
	struct _coap_pkg_list_t *next;	
}coap_msg_list_t;






#endif
