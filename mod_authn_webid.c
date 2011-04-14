/* mod_authn_webid
 * WebID FOAF+SSL authentication module for Apache 2
 *
 * Joe Presbrey <presbrey@csail.mit.edu>
 *
 * $Id$
 */

#include "apr_strings.h"
#define APR_WANT_STRFUNC
#include "apr_want.h"

#include "ap_config.h"
#include "httpd.h"
#include "http_config.h"
#include "http_core.h"
#include "http_log.h"
#include "http_request.h"

#include "mod_auth.h"
#include "mod_ssl.h"

#include "openssl/ssl.h"
#include "redland.h"

#define UD_WEBID_KEY "mod_authn_webid:client_WebID"
#define UD_TTL_KEY "mod_authn_webid:client_TTL"

#define SPARQL_WEBID \
    "PREFIX rdf: <http://www.w3.org/1999/02/22-rdf-syntax-ns#>" \
    "PREFIX cert: <http://www.w3.org/ns/auth/cert#>" \
    "PREFIX rsa: <http://www.w3.org/ns/auth/rsa#>" \
    "SELECT ?m ?e ?mod ?exp WHERE {" \
    "  ?key cert:identity <%s>; rsa:modulus ?m; rsa:public_exponent ?e." \
    "  OPTIONAL { ?m cert:hex ?mod. }" \
    "  OPTIONAL { ?e cert:decimal ?exp. }" \
    "}"

static APR_OPTIONAL_FN_TYPE(ssl_var_lookup) *ssl_var_lookup;

// 2010-09-28 tested against httpd-trunk r1002363
#if AP_MODULE_MAGIC_AT_LEAST(20060101,0)
static APR_OPTIONAL_FN_TYPE(ssl_ext_list) *ssl_ext_list;
#else
static APR_OPTIONAL_FN_TYPE(ssl_ext_lookup) *ssl_ext_lookup;
#endif

typedef struct {
    int authoritative;
} authn_webid_config_rec;

static void *
create_authn_webid_dir_config(apr_pool_t *p, char *dirspec) {
    authn_webid_config_rec *conf = apr_pcalloc(p, sizeof(*conf));

    conf->authoritative = -1;
    return conf;
}

static void *
merge_authn_webid_dir_config(apr_pool_t *p, void *parent_conf, void *newloc_conf) {
    authn_webid_config_rec *pconf = parent_conf, *nconf = newloc_conf,
    *conf = apr_pcalloc(p, sizeof(*conf));

    conf->authoritative = (nconf->authoritative != -1) ?
        nconf->authoritative : pconf->authoritative;
    return conf;
}

static const command_rec
authn_webid_cmds[] = {
    AP_INIT_FLAG("AuthWebIDAuthoritative", ap_set_flag_slot,
                 (void *)APR_OFFSETOF(authn_webid_config_rec, authoritative),
                 OR_AUTHCFG,
                 "Set to 'Off' to allow access control to be passed along to "
                 "lower modules if the WebID is not known to this module"),
    {NULL}
};

module AP_MODULE_DECLARE_DATA authn_webid_module;

static int
hex_or_x(int c) {
    if (c >= '0' && c <= '9')
        return c;
    c |= 32;
    if (c >= 'a' && c <= 'f')
        return c;
    return 'x';
}

static int
matches_pkey(unsigned char *s, char *pkey) {
    if (s == NULL || pkey == NULL)
        return 0;
    unsigned int s_s = strlen((const char*)s);
    unsigned int s_pkey = strlen(pkey);
    unsigned int fc, pc, j, k = 0;

    for (j = 0; j < s_s; j++) {
        if ((fc = hex_or_x(s[j])) == 'x')
            continue;
        pc = hex_or_x(pkey[k]);
        if (fc != pc)
            break;
        k++;
    }
    if (k == s_pkey)
        return 1;
    return 0;
}

static int
validate_webid(request_rec *request, const char *subjAltName, char *pkey_n, unsigned int pkey_e_i) {
    int r = HTTP_UNAUTHORIZED;

    librdf_world *rdf_world = NULL;
    librdf_storage *rdf_storage = NULL;
    librdf_model *rdf_model = NULL;
    librdf_query *rdf_query = NULL;
    librdf_query_results *rdf_query_results = NULL;

    rdf_world = librdf_new_world();
    if (rdf_world != NULL) {
        librdf_world_open(rdf_world);
        rdf_storage = librdf_new_storage(rdf_world, "uri", subjAltName, NULL);
        if (rdf_storage != NULL) {
            rdf_model = librdf_new_model(rdf_world, rdf_storage, NULL);
        } else
            ap_log_rerror(APLOG_MARK, APLOG_ERR, 0, request, "WebID: librdf_new_storage returned NULL");
    }

    if (rdf_model != NULL) {
        char *c_query = apr_psprintf(request->pool, SPARQL_WEBID, subjAltName);
        ap_log_rerror(APLOG_MARK, APLOG_DEBUG, 0, request, "WebID: SPARQL query   = %s", c_query);
        rdf_query = librdf_new_query(rdf_world, "sparql", NULL, (unsigned char*)c_query, NULL);
    } else {
        ap_log_rerror(APLOG_MARK, APLOG_ERR, 0, request, "WebID: librdf_new_query returned NULL");
    }

    if (rdf_query != NULL) {
        rdf_query_results = librdf_query_execute(rdf_query, rdf_model);
        if (rdf_query_results != NULL) {
            for (; r != OK && librdf_query_results_finished(rdf_query_results)==0; librdf_query_results_next(rdf_query_results)) {
                librdf_node *m_node, *e_node;
                unsigned char *rdf_mod;
                unsigned char *rdf_exp;
                if (r != OK
                    && NULL != (m_node = librdf_query_results_get_binding_value_by_name(rdf_query_results, "m"))
                    && NULL != (e_node = librdf_query_results_get_binding_value_by_name(rdf_query_results, "e"))) {
                    if (librdf_node_get_type(m_node) != LIBRDF_NODE_TYPE_LITERAL) {
                        librdf_free_node(m_node);
                        m_node = librdf_query_results_get_binding_value_by_name(rdf_query_results, "mod");
                    }
                    if (librdf_node_get_type(e_node) != LIBRDF_NODE_TYPE_LITERAL) {
                        librdf_free_node(e_node);
                        e_node = librdf_query_results_get_binding_value_by_name(rdf_query_results, "exp");
                    }
                    if (librdf_node_get_type(m_node) == LIBRDF_NODE_TYPE_LITERAL
                        && librdf_node_get_type(e_node) == LIBRDF_NODE_TYPE_LITERAL) {
                        rdf_mod = librdf_node_get_literal_value(m_node);
                        rdf_exp = librdf_node_get_literal_value(e_node);
                        ap_log_rerror(APLOG_MARK, APLOG_DEBUG, 0, request, "WebID: modulus = %s", rdf_mod);
                        ap_log_rerror(APLOG_MARK, APLOG_DEBUG, 0, request, "WebID: exponent = %s", rdf_exp);
                        if (rdf_exp != NULL
                            && apr_strtoi64((char*)rdf_exp, NULL, 10) == pkey_e_i
                            && matches_pkey(rdf_mod, pkey_n))
                            r = OK;
                        librdf_free_node(m_node);
                        librdf_free_node(e_node);
                    }
                }
            }
            librdf_free_query_results(rdf_query_results);
        } else
            ap_log_rerror(APLOG_MARK, APLOG_ERR, 0, request, "WebID: librdf_query_execute returned NULL");
        librdf_free_query(rdf_query);
    } else
        ap_log_rerror(APLOG_MARK, APLOG_ERR, 0, request, "WebID: librdf_new_query returned NULL");

    if (rdf_model) librdf_free_model(rdf_model);
    if (rdf_storage) librdf_free_storage(rdf_storage);
    if (rdf_world) librdf_free_world(rdf_world);

    return r;
}

char *
get_list_item(apr_pool_t *p, const char **field) {
    const char *tok_start;
    const unsigned char *ptr;
    unsigned char *pos;
    char *token;
    int addspace = 0, in_qpair = 0, in_qstr = 0, in_com = 0, tok_len = 0;

    if ((tok_start = ap_size_list_item(field, &tok_len)) == NULL) {
        return NULL;
    }
    token = apr_palloc(p, tok_len + 1);

    for (ptr = (const unsigned char *)tok_start, pos = (unsigned char *)token;
         *ptr && (in_qpair || in_qstr || in_com || *ptr != ',');
         ++ptr) {

        if (in_qpair) {
            in_qpair = 0;
            *pos++ = *ptr;
        }
        else {
            switch (*ptr) {
                case '\\': in_qpair = 1;
                           if (addspace == 1)
                               *pos++ = ' ';
                           *pos++ = *ptr;
                           addspace = 0;
                           break;
                case '"' : if (!in_com)
                               in_qstr = !in_qstr;
                           if (addspace == 1)
                               *pos++ = ' ';
                           *pos++ = *ptr;
                           addspace = 0;
                           break;
                case '(' : if (!in_qstr)
                               ++in_com;
                           if (addspace == 1)
                               *pos++ = ' ';
                           *pos++ = *ptr;
                           addspace = 0;
                           break;
                case ')' : if (in_com)
                               --in_com;
                           *pos++ = *ptr;
                           addspace = 0;
                           break;
                case ' ' :
                case '\t': if (addspace)
                               break;
                           if (in_com || in_qstr)
                               *pos++ = *ptr;
                           else
                               addspace = 1;
                           break;
                case '=' :
                case '/' :
                case ';' : if (!(in_com || in_qstr))
                               addspace = -1;
                           *pos++ = *ptr;
                           break;
                default  : if (addspace == 1)
                               *pos++ = ' ';
                           *pos++ = *ptr;
                           addspace = 0;
                           break;
            }
        }
    }
    *pos = '\0';

    return token;
}

static int
authenticate_webid_user(request_rec *request) {
    int r = 0;
    authn_webid_config_rec *conf =
        ap_get_module_config(request->per_dir_config, &authn_webid_module);
    if (!conf->authoritative) r = DECLINED;
    else r = HTTP_UNAUTHORIZED;

    /* Check for AuthType WebID */
    const char *current_auth = ap_auth_type(request);
    if (!current_auth || strcasecmp(current_auth, "WebID") != 0) {
        return DECLINED;
    }
    request->ap_auth_type = "WebID";

    /* Check for WebID cached in SSL session */
    const char *subjAltName = NULL;
    {
        void *data = NULL;
        if (apr_pool_userdata_get(&data, UD_WEBID_KEY, request->connection->pool) == APR_SUCCESS && data != NULL) {
            subjAltName = data;
            ap_log_rerror(APLOG_MARK, APLOG_DEBUG, 0, request, "WebID: using cached URI <%s>", subjAltName);
            if (strlen(subjAltName)) {
                request->user = (char *)subjAltName;
                r = OK;
            }
            return r;
        }
    }
#if AP_MODULE_MAGIC_AT_LEAST(20060101,0)
    apr_array_header_t *subjAltName_list = ssl_ext_list(request->pool, request->connection, 1, "2.5.29.17");
#else
    subjAltName = ssl_ext_lookup(request->pool, request->connection, 1, "2.5.29.17");
#endif

    /* Load X509 Public Key + Exponent */
    char *pkey_n = NULL;
    char *pkey_e = NULL;
    unsigned int pkey_e_i = 0;
#if AP_MODULE_MAGIC_AT_LEAST(20060101,0)
    if (subjAltName_list != NULL) {
#else
    if (subjAltName != NULL) {
#endif
        char *c_cert = NULL;
        BIO *bio_cert = NULL;
        X509 *x509 = NULL;
        EVP_PKEY *pkey = NULL;
        RSA *rsa = NULL;

        BIO *bio = NULL;
        BUF_MEM *bptr = NULL;

        if (NULL != (c_cert = ssl_var_lookup(request->pool, request->server, request->connection, request, "SSL_CLIENT_CERT"))
            && NULL != (bio_cert = BIO_new_mem_buf(c_cert, strlen(c_cert)))
            && NULL != (x509 = PEM_read_bio_X509(bio_cert, NULL, NULL, NULL))
            && NULL != (pkey = X509_get_pubkey(x509))
            && NULL != (rsa = EVP_PKEY_get1_RSA(pkey))) {

            // public key modulus
            bio = BIO_new(BIO_s_mem());
            BN_print(bio, rsa->n);
            BIO_get_mem_ptr(bio, &bptr);
            pkey_n = apr_pstrndup(request->pool, bptr->data, bptr->length);
            BIO_free(bio);

            // public key exponent
            bio = BIO_new(BIO_s_mem());
            BN_print(bio, rsa->e);
            BIO_get_mem_ptr(bio, &bptr);
            pkey_e = apr_pstrndup(request->pool, bptr->data, bptr->length);
            pkey_e_i = apr_strtoi64(pkey_e, NULL, 16);
            BIO_free(bio);
        } else {
            ap_log_rerror(APLOG_MARK, APLOG_WARNING, 0, request, "WebID: invalid client SSL certificate");
        }

        if (rsa)
            RSA_free(rsa);
        if (pkey)
            EVP_PKEY_free(pkey);
        if (x509)
            X509_free(x509);
        if (bio_cert)
            BIO_free(bio_cert);
    }

    if (pkey_n != NULL && pkey_e != NULL) {
#if AP_MODULE_MAGIC_AT_LEAST(20060101,0)
        const char *san;
        char *tok;
        int i;
        for (i = 0; i < subjAltName_list->nelts; i++) {
            san = APR_ARRAY_IDX(subjAltName_list, i, const char*);
            while ((tok = get_list_item(request->pool, &san)) != NULL) {
                if (strncmp(tok, "URI:", 4) == 0) {
                    if (validate_webid(request, tok+4, pkey_n, pkey_e_i) == OK) {
                        subjAltName = tok+4;
                        r = OK;
                        break;
                    }
                }
            }
        }
#else
        ap_log_rerror(APLOG_MARK, APLOG_DEBUG, 0, request, "WebID: subjectAltName = %s", subjAltName);
        ap_log_rerror(APLOG_MARK, APLOG_DEBUG, 0, request, "WebID: client pkey.n  = %s", pkey_n);
        ap_log_rerror(APLOG_MARK, APLOG_DEBUG, 0, request, "WebID: client pkey.e  = %d (%s)", pkey_e_i, pkey_e);
        const char *san = subjAltName;
        char *tok;
        while ((tok = get_list_item(request->pool, &san)) != NULL) {
            if (strncmp(tok, "URI:", 4) == 0) {
                if (validate_webid(request, tok+4, pkey_n, pkey_e_i) == OK) {
                    subjAltName = tok+4;
                    r = OK;
                    break;
                }
            }
        }
#endif
    }

    if (r == OK) {
        ap_log_rerror(APLOG_MARK, APLOG_INFO | APLOG_TOCLIENT, 0, request, "WebID: authentication (%sauthoritative) succeeded for <%s> pubkey: \"%s\", URI: <%s>", conf->authoritative?"":"non-", subjAltName, pkey_n, request->uri);
        request->user = apr_psprintf(request->connection->pool, "%s", subjAltName);
    } else {
        ap_log_rerror(APLOG_MARK, (conf->authoritative?APLOG_WARNING:APLOG_INFO) | APLOG_TOCLIENT, 0, request, "WebID: authentication (%sauthoritative) failed for <%s> pubkey: \"%s\", URI: <%s>", conf->authoritative?"":"non-", subjAltName, request->uri, pkey_n);
        subjAltName = "";
    }
    ap_log_rerror(APLOG_MARK, APLOG_DEBUG, 0, request, "WebID: setting cached URI <%s>", subjAltName);
    apr_pool_userdata_set(apr_pstrdup(request->connection->pool, subjAltName), UD_WEBID_KEY, NULL, request->connection->pool);

    return r;
}

static void
import_ssl_func() {
    ssl_var_lookup = APR_RETRIEVE_OPTIONAL_FN(ssl_var_lookup);
#if AP_MODULE_MAGIC_AT_LEAST(20060101,0)
    ssl_ext_list = APR_RETRIEVE_OPTIONAL_FN(ssl_ext_list);
#else
    ssl_ext_lookup = APR_RETRIEVE_OPTIONAL_FN(ssl_ext_lookup);
#endif
}

static void
register_hooks(apr_pool_t *p) {
#if AP_MODULE_MAGIC_AT_LEAST(20080403,1)
    ap_hook_check_authn(authenticate_webid_user, NULL, NULL, APR_HOOK_MIDDLE, AP_AUTH_INTERNAL_PER_URI);
#else
    ap_hook_check_user_id(authenticate_webid_user, NULL, NULL, APR_HOOK_MIDDLE);
#endif
    ap_hook_optional_fn_retrieve(import_ssl_func, NULL, NULL, APR_HOOK_MIDDLE);
}

module AP_MODULE_DECLARE_DATA
authn_webid_module = {
    STANDARD20_MODULE_STUFF,
    create_authn_webid_dir_config,
    merge_authn_webid_dir_config,
    NULL,
    NULL,
    authn_webid_cmds,
    register_hooks
};
