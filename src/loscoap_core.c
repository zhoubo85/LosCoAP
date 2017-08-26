#include "../include/los_coap.h"
#include "../include/los_coap_err.h"
#include <string.h>

int los_coap_parse_header(coap_msg_t *msg, const unsigned char *buf, int buflen)
{
    if (NULL == msg || NULL == buf)
        return -LOS_COAP_PARAM_NULL;
    if (buflen < 4)
        return -LOS_COAP_BUF_LEN_TOO_SMALL;
    
    msg->head.ver = (buf[0] & 0xC0) >> 6;
    if (msg->head.ver != 1)
        return -LOS_COAP_VER_ERR;
    
    msg->head.t = (buf[0] & 0x30) >> 4;
    msg->head.tkl = buf[0] & 0x0F;
    msg->head.code = buf[1];
    msg->head.msgid[0] = buf[2];
    msg->head.msgid[1] = buf[3];
    
    return 0;
}

int los_coap_parse_token(coap_msg_t *msg, unsigned char *buf, int buflen)
{
    if (NULL == msg || NULL == buf)
        return -LOS_COAP_PARAM_NULL;
    if (msg->head.tkl == 0)
    {
        msg->tok = NULL;
        return 0;
    }
    else if (msg->head.tkl <= 8)
    {
        if (4U + msg->head.tkl > buflen)
            return -LOS_COAP_BUF_LEN_TOO_SMALL;   // tok bigger than packet
        if (NULL == msg->tok)
        {
            msg->tok = (coap_token_t *)los_coap_malloc(sizeof(coap_token_t));
            if (NULL == msg->tok)
                return -LOS_COAP_MALLOC_FAILED;
        }
        msg->tok->token = (unsigned char *)los_coap_malloc(msg->head.tkl);
        if (NULL != msg->tok->token)
        {
            memcpy(msg->tok->token, buf+4, msg->head.tkl);  // skip header
            msg->tok->tklen = msg->head.tkl;
        }
        return 0;
    }
    else
    {
        // invalid size
        return -LOS_COAP_TOKEN_LEN_ERR;
    }
}

int los_coap_parse_one_option(coap_msg_t *msg, unsigned short *sumdelta, const unsigned char **buf, int buflen)
{
    const unsigned char *p = *buf;
    unsigned char headlen = 1;
    unsigned short len, delta;
    coap_option_t *newopt = NULL;
    coap_option_t *tmpopt = NULL;
    
    if (NULL == msg || NULL == sumdelta || NULL == buf)
        return -LOS_COAP_PARAM_NULL;//params err

    if (buflen < headlen) // too small
        return -LOS_COAP_BUF_LEN_TOO_SMALL;

    delta = (p[0] & 0xF0) >> 4;
    len = p[0] & 0x0F;

    // These are untested and may be buggy
    if (delta == 13)
    {
        headlen++;
        if (buflen < headlen)
            return -LOS_COAP_BUF_LEN_TOO_SMALL;
        delta = p[1] + 13;
        p++;
    }
    else
    if (delta == 14)
    {
        headlen += 2;
        if (buflen < headlen)
            return -LOS_COAP_BUF_LEN_TOO_SMALL;
        delta = ((p[1] << 8) | p[2]) + 269;
        p+=2;
    }
    else
    if (delta == 0x000f)
        return -LOS_COAP_OPTION_DELTA_ERR;

    if (len == 13)
    {
        headlen++;
        if (buflen < headlen)
            return -LOS_COAP_BUF_LEN_TOO_SMALL;
        len = p[1] + 13;
        p++;
    }
    else
    if (len == 14)
    {
        headlen += 2;
        if (buflen < headlen)
            return -LOS_COAP_BUF_LEN_TOO_SMALL;
        len = ((p[1] << 8) | p[2]) + 269;
        p+=2;
    }
    else
    if (len == 15)
        return -LOS_COAP_OPTION_LEN_ERR;

    if ((p + 1 + len) > (*buf + buflen))
        return -LOS_COAP_OPTION_LEN_ERR;

    //printf("option num=%d\n", delta + *running_delta);
    
    newopt = (coap_option_t *)los_coap_malloc(sizeof(coap_option_t));
    if (NULL == newopt)
    {
        return -LOS_COAP_MALLOC_FAILED;
    }
    newopt->optnum = delta + *sumdelta;
    
    newopt->value = (unsigned char *)los_coap_malloc(len);
    if (NULL != newopt->value)
    {
        newopt->optlen = len;
        memcpy(newopt->value, p+1, len);
    }
    
    newopt->next = NULL;
    msg->optcnt++;
    tmpopt = msg->option;
    if (tmpopt == NULL)
    {
        msg->option = newopt;
    }
    else
    {
        while(tmpopt->next != NULL)
        {
            tmpopt = tmpopt->next;
        }
        tmpopt->next = newopt;
    }

    //option->num = delta + *running_delta;
    //option->buf.p = p+1;
    //option->buf.len = len;
    //coap_dump(p+1, len, false);

    // advance buf
    *buf = p + 1 + len;
    *sumdelta += delta;

    return 0;
}

int los_coap_parse_opts_payload(coap_msg_t *msg, const unsigned char *buf, int buflen)
{
    unsigned short sumdelta = 0;
    const unsigned char *p = NULL;
    const unsigned char *end = buf + buflen;
    int ret;
    
    if (NULL == msg || NULL == buf || buflen <= 4)
        return -LOS_COAP_PARAM_NULL;//param err
    
    p = buf + 4 + msg->head.tkl;
    
    if (p > end)
        return -LOS_COAP_OPTION_OVERRUN_ERR;
    
    while((p < end) && (*p != 0xFF))
    {
        ret = los_coap_parse_one_option(msg, &sumdelta, &p, end-p);
        if (0 != ret)
            return ret;
    }
    
    if (p+1 < end && *p == 0xFF)  // payload marker
    {
        //msg->payload = (unsigned char *)p + 1;
        msg->payloadlen = end-(p+1);
        msg->payload = (unsigned char *)los_coap_malloc(msg->payloadlen);
        if (NULL != msg->payload)
            memcpy(msg->payload, (unsigned char *)p + 1, msg->payloadlen);
        else
            msg->payloadlen = 0;
    }
    else
    {
        msg->payload = NULL;
        msg->payloadlen = 0;
    }
    msg->payloadmarker = 0xFF;
    
    return 0;
}

static int los_coap_encode_option(coap_option_t *opt, int lastoptval, unsigned char *outbuf, int *len)
{
    int delta = 0;
    int delta_ex = 0;
    int optlen = 0;
    int optlen_ex = 0;
    unsigned char tmp;
    int sumlen = 0;
    
    if (NULL == opt || NULL == outbuf || NULL == len)
        return -LOS_COAP_PARAM_NULL;
    if (opt->optnum < lastoptval)
        return -LOS_COAP_OPTION_POSTION_ERR;
    
    delta = opt->optnum - lastoptval;
    if (delta < 13)
    {
        delta = opt->optnum - lastoptval;
        delta_ex = 0;
    } 
    else if (delta < 269)
    {
        delta_ex = delta - 13;
        delta = 13;
    }
    else if (delta >= 269)
    {
        delta_ex = delta - 269 - 14;
        delta = 14;
    }

    optlen = opt->optlen;
    if (optlen < 13)
    {
        optlen = opt->optlen;
        optlen_ex = 0;
    } 
    else if (optlen < 269)
    {
        optlen_ex = optlen - 13;
        optlen = 13;
    }
    else if (optlen >= 269)
    {
        optlen_ex = optlen - 269 - 14;
        optlen = 14;
    }
    
    tmp = (unsigned char)delta;
    outbuf[0] = tmp << 4;
    tmp = (unsigned char)optlen;
    outbuf[0] |= tmp &0x0f;
    sumlen = 1;
    if(delta == 13)
    {
        outbuf[sumlen] = delta_ex;
        sumlen++;
    }
    if(delta == 14)
    {
        outbuf[sumlen] = (delta_ex & 0x0000ffff) >> 8;
        outbuf[sumlen + 1] = (delta_ex & 0x000000ff);
        sumlen += 2;
    }
    if(optlen == 13)
    {
        //offset
        outbuf[sumlen] = optlen_ex;
        sumlen++;
    }
    if(optlen == 14)
    {
        outbuf[sumlen] = (optlen_ex & 0x0000ffff) >> 8;
        outbuf[sumlen+1] = (optlen_ex & 0x000000ff);
        sumlen += 2;
    }
    memcpy(outbuf + sumlen, opt->value, opt->optlen);
    
    *len = sumlen + opt->optlen;
    return 0;
}
int los_coap_build_byte_steam(coap_context_t *ctx, coap_msg_t *msg)
{
    int len = 0;
    int offset = 0;
    coap_option_t *tmp = NULL;
    int sumdelta = 0;
    int msglen = 0;
    
    if (NULL == ctx || NULL == msg)
        return -LOS_COAP_PARAM_NULL;
    
    if (NULL == ctx->sndbuf.buf)
        return -LOS_COAP_CONTEX_BUF_NULL;
    tmp = msg->option;
    while(NULL != tmp)
    {
        len += 1 + 4 + tmp->optlen;
        tmp = tmp->next;
    }
    //option len(x) + tokenlen(0~8) + heanderlen(4) + marker(1)
    if (NULL != msg->tok)
        len += msg->tok->tklen + msg->payloadlen + 4 + 1;
    else
        len += msg->payloadlen + 4 + 1;
    
    if (len > ctx->sndbuf.len)
        return -LOS_COAP_SND_LEN_TOO_BIG;
  
    //encode header
    //memcpy(ctx->sndbuf.buf + offset, &msg->head, sizeof(msg->head));
    ctx->sndbuf.buf[0] = ((msg->head.ver & 0x03) << 6);
    ctx->sndbuf.buf[0] |= ((msg->head.t & 0x03) << 4);
    ctx->sndbuf.buf[0] |= (msg->head.tkl & 0x0F);
    ctx->sndbuf.buf[1] = msg->head.code;
    ctx->sndbuf.buf[2] = msg->head.msgid[0];
    ctx->sndbuf.buf[3] = msg->head.msgid[1];
    offset = 4;
    if (NULL != msg->tok)
    {
        memcpy(ctx->sndbuf.buf + offset, msg->tok->token, msg->tok->tklen);
        offset += msg->tok->tklen;
    }

    //encode options
    len = 0;
    tmp = msg->option;
    while(NULL != tmp)
    {
        los_coap_encode_option(tmp, sumdelta, ctx->sndbuf.buf + offset, &len);
        offset = offset + len;
        len = 0;
        sumdelta = tmp->optnum;
        tmp = tmp->next;
    }
    msglen = msglen + offset;
    //encode payload
    if (NULL != msg->payload)
    {
        ctx->sndbuf.buf[offset] = msg->payloadmarker;
        memcpy(ctx->sndbuf.buf + offset + 1, msg->payload, msg->payloadlen);
        msglen = msglen + msg->payloadlen + 1;
    }
    
    return msglen;
}

coap_option_t * los_coap_add_option_to_list(coap_option_t *head, 
								unsigned short option, 
								char *value, int len)
{
    coap_option_t *tmp = NULL;
    coap_option_t *next = NULL;
    coap_option_t *newopt = NULL;
    if (NULL == value || 0 == len)
    {
        return NULL;
    }
    
    newopt = (coap_option_t *)los_coap_malloc(sizeof(coap_option_t));
    if (NULL == newopt)
    {
        return head;
    }
    newopt->optnum = option;
    newopt->optlen = len;
    newopt->value = (unsigned char *)los_coap_malloc(len);
    if(NULL == newopt->value)
    {
        los_coap_free(newopt);
        return head;
    }
    //newopt->value = (unsigned char *)value;
    memcpy(newopt->value, value, len);
    newopt->next = NULL;
    
    // note that head just a pointer, point to the fisrt node of options
    tmp = head;
    if (NULL == head)
    {
        return newopt;
    }
    if (tmp->optnum > option)
    {
        // option number is the smallest in the list
        newopt->next = head;
        return newopt;
    }
    next = tmp->next;
    while(NULL != tmp && NULL != next)
    {
        if (tmp->optnum <= option && next->optnum > option)
        {
            tmp->next = newopt;
            newopt->next = next;
            break;
        }
        else
        {
            tmp = tmp->next;
            next = tmp->next;
        }
    }
    tmp->next = newopt;
    newopt->next = next;
    
    return head;
}

int los_coap_add_token(coap_msg_t *msg, char *tok, int tklen)
{
    if (NULL == msg || tklen < 0 || tklen > COAP_TOKEN_LEN_MAX)
    {
        return -LOS_COAP_PARAM_NULL;
    }
    if (NULL == msg->tok)
    {
        msg->tok = (coap_token_t *)los_coap_malloc(sizeof(coap_token_t));
        if (NULL ==  msg->tok)
        {
            return -LOS_COAP_MALLOC_FAILED;
        }
    }
    msg->tok->token = (unsigned char *)los_coap_malloc(tklen);
    if (NULL == msg->tok->token)
        return -LOS_COAP_MALLOC_FAILED;
    memcpy(msg->tok->token, tok, tklen);
    msg->tok->tklen = tklen;
    msg->head.tkl = tklen;
    return 0;
}

coap_msg_t *los_coap_new_msg(coap_context_t *ctx,
								unsigned char msgtype, 
								unsigned char code, 
								coap_option_t *optlist, 
								unsigned char *payload, 
								int payloadlen)
{
    coap_msg_t *msg = NULL;
    if (NULL == ctx)
    {
        return NULL;
    }
    
    if (msgtype > COAP_MESSAGE_RST)
    {
        return NULL;
    }
    
    msg = (coap_msg_t *)los_coap_malloc(sizeof(coap_msg_t));
    if (NULL == msg)
    {
        return NULL;
    }
    msg->head.t = msgtype;
    msg->head.ver = 1;
    ctx->msgid++;
    msg->head.msgid[0] = (unsigned char)((ctx->msgid)&0x00ff);
    msg->head.msgid[1] = (unsigned char)((ctx->msgid&0xff00)>>8);
    msg->head.code = code;
    msg->option = optlist;
    if (NULL != payload)
    {
        msg->payload = (unsigned char *)los_coap_malloc(payloadlen);
        if (NULL != msg->payload)
        {
            memcpy(msg->payload, payload, payloadlen);
            msg->payloadlen = payloadlen;
        }
    }
    return msg;
}

int los_coap_delete_msg(coap_msg_t *msg)
{
    coap_option_t *tmp = NULL;
    coap_option_t *next = NULL;
    if (NULL == msg)
        return -LOS_COAP_PARAM_NULL;
    
    if (msg->tok)
    {
        los_coap_free(msg->tok->token);
        los_coap_free(msg->tok);
        msg->tok = NULL;
    }
    
    tmp = msg->option;
    while(NULL != tmp)
    {
        next = tmp->next;
        los_coap_free(tmp->value);
        los_coap_free(tmp);
        tmp = next;
    }
    if (NULL != msg->payload)
        los_coap_free(msg->payload);
    
    los_coap_free(msg);
    
    return 0;
}


int los_coap_send_back(coap_context_t *ctx, coap_msg_t *rcvmsg, unsigned char type)
{
    coap_msg_t *newmsg = NULL;
    int datalen = 0;
    
    if (NULL == ctx || NULL == rcvmsg)
        return -LOS_COAP_PARAM_NULL;
    newmsg = (coap_msg_t *)los_coap_malloc(sizeof(coap_msg_t));
    if (NULL == newmsg)
        return -LOS_COAP_MALLOC_FAILED;
    
    newmsg->head.t = type;
    newmsg->head.ver = 1;
    newmsg->head.msgid[0] = rcvmsg->head.msgid[0];
    newmsg->head.msgid[1] = rcvmsg->head.msgid[0];
    newmsg->head.code = 0;
    newmsg->option = NULL;
    newmsg->payload = NULL;
    newmsg->payloadlen = 0;
    
    datalen = los_coap_build_byte_steam(ctx, newmsg);
    if (datalen < 0)
        return -LOS_COAP_ENCODE_PKG_SIZE_ERR;
    //send msg to net work
    ctx->netops->network_send(ctx->udpio, (char *)ctx->sndbuf.buf, datalen);
    los_coap_free(newmsg);
    return 0;
}

int los_coap_send_rst(coap_context_t *ctx, coap_msg_t *rcvmsg)
{
    int ret = 0;
    ret = los_coap_send_back(ctx, rcvmsg, COAP_MESSAGE_RST);
    return ret;
}

int los_coap_send_ack(coap_context_t *ctx, coap_msg_t *rcvmsg)
{
    int ret = 0;
    ret = los_coap_send_back(ctx, rcvmsg, COAP_MESSAGE_ACK);
    return ret;
}

int los_coap_register_handler(coap_context_t *ctx, msghandler func)
{
    if (NULL == ctx)
    {
        return -LOS_COAP_PARAM_NULL;
    }
    ctx->response_handler = func;
    return 0;
}

int los_coap_addto_sndqueue(coap_context_t *ctx, coap_msg_t *msg)
{
    send_queue_t *tmp = NULL;
    if (NULL == ctx || NULL == msg)
        return -LOS_COAP_PARAM_NULL;
    
    tmp = (send_queue_t *)los_coap_malloc(sizeof(send_queue_t));
    if (NULL == tmp)
        return -LOS_COAP_MALLOC_FAILED;
    
    tmp->msg = msg;
    tmp->next = ctx->sndque;
    ctx->sndque = tmp;
    
    return 0;
}

int los_coap_remove_sndqueue(coap_context_t *ctx, coap_msg_t *rcvmsg)
{
    send_queue_t *tmp = NULL;
    send_queue_t *before = NULL;
    if (NULL == ctx || NULL == rcvmsg)
        return -LOS_COAP_PARAM_NULL;
    
    //before = ctx->sndque;
    tmp = ctx->sndque;
    while(NULL != tmp)
    {
        if (memcmp(rcvmsg->head.msgid, tmp->msg->head.msgid, 2) == 0)
        {
            if (NULL == before)
                ctx->sndque = tmp->next;
            else
                before->next = tmp->next;
            los_coap_delete_msg(tmp->msg);
            los_coap_free(tmp);
            break;
        }
        before = tmp;
        tmp = tmp->next;   
    }
    
    return 0;
}

int los_coap_add_resource(coap_context_t *ctx, coap_res_t *res)
{
    if (NULL == ctx)
        return -LOS_COAP_PARAM_NULL;
    
    ctx->res = res;
    return 0;
}

//note: this func is for the future, now we don't use it
int los_coap_option_check_critical(coap_msg_t *msg)
{
    unsigned short option;
    switch(option)
    {
        
    }
    return 0;
}

int los_coap_handle_request(coap_context_t *ctx, coap_msg_t *rcvmsg)
{
    coap_res_t *res = NULL;
    coap_option_t *tmp = NULL;
    coap_option_t *opthead = NULL;
    coap_msg_t *respmsg = NULL;
    char contype[2] = {0xff,0xff};
    int i = 0;
    
    if (NULL == ctx || NULL == rcvmsg)
        return -LOS_COAP_PARAM_NULL;
    res = ctx->res;
    while(NULL != res->handler)
    {
        //find if the res is in the ctx->res
        if (res->method != rcvmsg->head.code)
        {
            res++;
            continue;
        }
        if(0 != rcvmsg->optcnt && res->path->count == rcvmsg->optcnt)
        {
            tmp = rcvmsg->option;
            for(i = 0; i < rcvmsg->optcnt; i++)
            {
                if(tmp->optlen != strlen(res->path->elems[i]))
                {
                    tmp = tmp->next;
                    break;
                }
                if (0 != memcmp(res->path->elems[i], tmp->value, tmp->optlen))
                {
                    tmp = tmp->next;
                    break;
                }
            }
            if (i == rcvmsg->optcnt)
            {
                //respmsg = (coap_msg_t *)los_coap_malloc(sizeof(coap_msg_t));
                if (rcvmsg->head.t == COAP_MESSAGE_CON)
                    respmsg = los_coap_new_msg(ctx,COAP_MESSAGE_ACK, COAP_RESP_CODE(205), NULL,NULL, 0);
                else
                    respmsg = los_coap_new_msg(ctx,COAP_MESSAGE_NON, COAP_RESP_CODE(205), NULL,NULL, 0);
                
                los_coap_add_token(respmsg, (char *)rcvmsg->tok->token, rcvmsg->tok->tklen);
                
                if (NULL == respmsg)
                    return -1;
                //match the option, so deliver msg to resource handler function 
                res->handler(rcvmsg, respmsg);
                //send to remote
                los_coap_send(ctx, respmsg);
            }
            else
            {
                opthead = los_coap_add_option_to_list(opthead, COAP_OPTION_CONTENT_FORMAT, contype, 2);
                //respmsg = (coap_msg_t *)los_coap_malloc(sizeof(coap_msg_t));
                if (rcvmsg->head.t == COAP_MESSAGE_CON)
                    respmsg = los_coap_new_msg(ctx,COAP_MESSAGE_ACK, COAP_RESP_CODE(404), opthead, NULL, 0);
                else
                    respmsg = los_coap_new_msg(ctx,COAP_MESSAGE_NON, COAP_RESP_CODE(404), opthead, NULL, 0);
                
                los_coap_add_token(respmsg, (char *)rcvmsg->tok->token, rcvmsg->tok->tklen);
                
                if (NULL == respmsg)
                    return -1;
                //send to remote
                los_coap_send(ctx, respmsg);
            }
        }
    }
    return 0;
}


int los_coap_handle_msg(coap_context_t *ctx, coap_msg_t *msg)
{
    switch(msg->head.t)
    {
        case COAP_MESSAGE_ACK:
            los_coap_remove_sndqueue(ctx, msg);
            break;
        case COAP_MESSAGE_RST:
            los_coap_remove_sndqueue(ctx, msg);
            break;
        case COAP_MESSAGE_NON :
        case COAP_MESSAGE_CON :
            //los_coap_send_ack(ctx, msg);
            break;
        default:
            break;
    }
    if (COAP_MSG_IS_REQUEST(msg))
    {
        //request from remote endpoint
        los_coap_handle_request(ctx, msg);
    }
    else if(COAP_MSG_IS_RESPONSE(msg))
    {
        //response data come , should call the callback function
        if (NULL != ctx->response_handler)
            ctx->response_handler(ctx, msg);
    }
    return 0;
}

int los_coap_read(coap_context_t *ctx)
{
    coap_msg_t *msg = NULL;
    int len = 0;
    int ret = 0;
    if (NULL == ctx)
    {
        return -LOS_COAP_PARAM_NULL;
    }
    len = ctx->netops->network_read(ctx->udpio, (char *)ctx->rcvbuf.buf, ctx->rcvbuf.len);
    //fixed me: need parse data and then handle coap message 
    //need malloc coap msg buffers, deal with it and then free, it
    msg = (coap_msg_t *)los_coap_malloc(sizeof(coap_msg_t));
    if (NULL == msg)
        return -LOS_COAP_MALLOC_FAILED;
    
    ret = los_coap_parse_header(msg, (const unsigned char *)ctx->rcvbuf.buf, len);
    if (ret < 0)
    {
        los_coap_delete_msg(msg);
        return -LOS_COAP_HEADER_ERR;
    }
    ret = los_coap_parse_token(msg, (unsigned char *)ctx->rcvbuf.buf, len);
    if (ret < 0)
    {
        los_coap_delete_msg(msg);
        return -LOS_COAP_TOKEN_ERR;
    }

    ret = los_coap_parse_opts_payload(msg, (const unsigned char *)ctx->rcvbuf.buf, len);
    if (ret < 0)
    {
        los_coap_delete_msg(msg);
        return -LOS_COAP_OPTION_ERR;
    }
    //if pack is ack, rst ... no need send anything, if con msg, send a ack and pass to response_handler
    los_coap_handle_msg(ctx, msg);
    los_coap_delete_msg(msg);
    return 0;
}

int los_coap_send(coap_context_t *ctx, coap_msg_t *msg)
{
    int slen = 0;
    int n = 0;
    if (NULL == ctx || NULL == msg)
    {
        return -LOS_COAP_PARAM_NULL;
    }
    if (msg->head.t == COAP_MESSAGE_CON)
    {
        los_coap_addto_sndqueue(ctx, msg);
    }
    //fixed me: need translate msg to bytes stream, and then send it.
    slen = los_coap_build_byte_steam(ctx, msg);
    if (slen > ctx->sndbuf.len)
    {
        //message is too long for ctx buf
        return -LOS_COAP_SND_LEN_TOO_BIG;
    }
    n = ctx->netops->network_send(ctx->udpio, (char *)ctx->sndbuf.buf, slen);
    //delete msg that do not need stored for retransmit
    if(n == slen && msg->head.t != COAP_MESSAGE_CON)
    {
        los_coap_delete_msg(msg);
    }
    return n;
}


