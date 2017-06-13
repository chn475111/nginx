/*
* lijk@infosec.com.cn
*/

#include <ngx_config.h>
#include <ngx_core.h>
#include <ngx_http.h>

typedef struct ngx_http_infosec_loc_conf_s
{
    ngx_str_t print;
}ngx_http_infosec_loc_conf_t;

static void *ngx_http_infosec_create_loc_conf(ngx_conf_t *cf);

static char *ngx_http_infosec_merge_loc_conf(ngx_conf_t *cf, void *parent, void *child);

static char *ngx_http_infosec_print(ngx_conf_t *cf, ngx_command_t *cmd, void *conf);

static ngx_command_t ngx_http_infosec_commands[] = 
{
    {
        ngx_string("print"),
        NGX_HTTP_LOC_CONF|NGX_CONF_TAKE1,
        ngx_http_infosec_print,
        NGX_HTTP_LOC_CONF_OFFSET,
        offsetof(ngx_http_infosec_loc_conf_t, print),
        NULL
    },

    ngx_null_command
};

static ngx_http_module_t ngx_http_infosec_module_ctx = 
{
    NULL,
    NULL,
    NULL,
    NULL,
    NULL,
    NULL,
    ngx_http_infosec_create_loc_conf,
    ngx_http_infosec_merge_loc_conf
};

ngx_module_t ngx_http_infosec_module = 
{
    NGX_MODULE_V1,
    &ngx_http_infosec_module_ctx,
    ngx_http_infosec_commands,
    NGX_HTTP_MODULE,
    NULL,
    NULL,
    NULL,
    NULL,
    NULL,
    NULL,
    NULL,
    NGX_MODULE_V1_PADDING
};

static void *ngx_http_infosec_create_loc_conf(ngx_conf_t *cf)
{
    ngx_http_infosec_loc_conf_t *conf;
    conf = ngx_pcalloc(cf->pool, sizeof(ngx_http_infosec_loc_conf_t));
    if(conf == NULL)
    {
        return NGX_CONF_ERROR;
    }

    ngx_str_null(&conf->print);
    ngx_conf_log_error(NGX_LOG_DEBUG, cf, 0, "create_loc_conf: %s", conf->print.data ? conf->print.data : (u_char*)"null");
    return conf;
}

static char *ngx_http_infosec_merge_loc_conf(ngx_conf_t *cf, void *parent, void *child)
{
    ngx_http_infosec_loc_conf_t *prev = parent;
    ngx_http_infosec_loc_conf_t *conf = child;

    ngx_conf_merge_str_value(conf->print, prev->print, "null");
    ngx_conf_log_error(NGX_LOG_DEBUG, cf, 0, "merge_loc_conf: %s", conf->print.data ? conf->print.data : (u_char*)"null");
    return NGX_CONF_OK;
}

static ngx_int_t ngx_http_infosec_print_handler(ngx_http_request_t *r)
{
    ngx_int_t rc;
    ngx_buf_t *b;
    ngx_chain_t out;
    ngx_http_infosec_loc_conf_t *conf;
    conf = ngx_http_get_module_loc_conf(r, ngx_http_infosec_module);

    if(!(r->method & (NGX_HTTP_HEAD|NGX_HTTP_GET|NGX_HTTP_POST)))
    {
        return NGX_HTTP_NOT_ALLOWED;
    }

    r->headers_out.content_type.len = sizeof("text/html") - 1;
    r->headers_out.content_type.data = (u_char*)"text/html";
    r->headers_out.status = NGX_HTTP_OK;
    r->headers_out.content_length_n = conf->print.len;

    if(r->method == NGX_HTTP_HEAD)
    {
        return ngx_http_send_header(r);
    }

    b = ngx_pcalloc(r->pool, sizeof(ngx_buf_t));
    if(b == NULL)
    {
        return NGX_HTTP_INTERNAL_SERVER_ERROR;
    }

    out.buf = b;
    out.next = NULL;
    b->pos = conf->print.data;
    b->last = conf->print.data + (conf->print.len);
    b->memory = 1;
    b->last_buf = 1;

    rc = ngx_http_send_header(r);
    if(rc != NGX_OK)
    {
        return rc;
    }

    ngx_log_error(NGX_LOG_DEBUG, r->connection->log, 0, "handler: %s", conf->print.data ? conf->print.data : (u_char*)"null");
    return ngx_http_output_filter(r, &out);
}

static char *ngx_http_infosec_print(ngx_conf_t *cf, ngx_command_t *cmd, void *conf)
{
    ngx_http_core_loc_conf_t *clcf;

    clcf = ngx_http_conf_get_module_loc_conf(cf, ngx_http_core_module);
    clcf->handler = ngx_http_infosec_print_handler;

    ngx_conf_set_str_slot(cf, cmd, conf);
    ngx_conf_log_error(NGX_LOG_DEBUG, cf, 0, "set: %s", clcf->name.data ? clcf->name.data : (u_char*)"null");
    return NGX_CONF_OK;
}
