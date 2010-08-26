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
static APR_OPTIONAL_FN_TYPE(ssl_ext_lookup) *ssl_ext_lookup;

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
            ap_log_rerror(APLOG_MARK, APLOG_DEBUG, 0, request, "get connection cached WebID: %s (%d)", subjAltName, subjAltName==NULL?0:(int)strlen(subjAltName));
            if (strlen(subjAltName)) {
                request->user = apr_psprintf(request->connection->pool, "<%s>", subjAltName);
                r = OK;
            }
            return r;
        }
    }

    /* Load X509 Public Key + Exponent */
    char *pkey_n = NULL;
    char *pkey_e = NULL;
    unsigned int pkey_e_i = 0;
    {
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
            ap_log_rerror(APLOG_MARK, APLOG_WARNING, 0, request, "WebID: invalid client certificate");
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

    subjAltName = ssl_ext_lookup(request->pool, request->connection, 1, "2.5.29.17");
    if (subjAltName != NULL) {
        if (strncmp(subjAltName, "URI:", 4) != 0)
            subjAltName = NULL;
        else
            subjAltName = subjAltName+4;
    }

    if (subjAltName != NULL && pkey_n != NULL && pkey_e != NULL) {
        ap_log_rerror(APLOG_MARK, APLOG_DEBUG, 0, request, "WebID: subjectAltName = %s", subjAltName);
        ap_log_rerror(APLOG_MARK, APLOG_DEBUG, 0, request, "WebID: client pkey.n  = %s", pkey_n);
        ap_log_rerror(APLOG_MARK, APLOG_DEBUG, 0, request, "WebID: client pkey.e  = %d (%s)", pkey_e_i, pkey_e);
        if (validate_webid(request, subjAltName, pkey_n, pkey_e_i) == OK)
            r = OK;
    }

    if (r == OK) {
        ap_log_rerror(APLOG_MARK, APLOG_INFO | APLOG_TOCLIENT, 0, request, "WebID authentication (%sauthoritative) succeeded: <%s> URI: <%s> Pubkey: \"%s\"", conf->authoritative?"":"non-", subjAltName, request->uri, pkey_n);
        request->user = apr_psprintf(request->connection->pool, "<%s>", subjAltName);
    } else {
        ap_log_rerror(APLOG_MARK, APLOG_WARNING | APLOG_TOCLIENT, 0, request, "WebID authentication (%sauthoritative) failed: <%s> URI: <%s> Pubkey: \"%s\"", conf->authoritative?"":"non-", subjAltName, request->uri, pkey_n);
        subjAltName = "";
    }
    ap_log_rerror(APLOG_MARK, APLOG_DEBUG, 0, request, "set connection cached WebID: %s", subjAltName);
    apr_pool_userdata_set(subjAltName, UD_WEBID_KEY, NULL, request->connection->pool);

    return r;
}

static void
import_ssl_func() {
    ssl_var_lookup = APR_RETRIEVE_OPTIONAL_FN(ssl_var_lookup);
    ssl_ext_lookup = APR_RETRIEVE_OPTIONAL_FN(ssl_ext_lookup);
}

static void
register_hooks(apr_pool_t *p) {
    ap_hook_check_user_id(authenticate_webid_user, NULL, NULL, APR_HOOK_MIDDLE);
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
