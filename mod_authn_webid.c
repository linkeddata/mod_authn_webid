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
    unsigned int s_s = strlen(s);
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

    {
        void *data = NULL;
        const char *webid;
        if (apr_pool_userdata_get(&data, UD_WEBID_KEY, request->connection->pool) == APR_SUCCESS && data != NULL) {
            webid = data;
            ap_log_rerror(APLOG_MARK, APLOG_DEBUG, 0, request, "using connection cached WebID: %s", webid);
            request->user = apr_pstrdup(request->pool, webid);
            return OK;
        }
    }

    const char *subjAltName;
    char *pkey_n = NULL;
    char *pkey_e = NULL;

    subjAltName = ssl_ext_lookup(request->pool, request->connection, 1, "2.5.29.17");
    if (subjAltName != NULL) {
        if (strncmp(subjAltName, "URI:", 4) != 0)
            subjAltName = NULL;
        else
            subjAltName = subjAltName+4;
    }

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
        BIO_free(bio);
    } else {
        ap_log_rerror(APLOG_MARK, APLOG_DEBUG, 0, request, "WebID: invalid client certificate");
    }

    if (rsa)
        RSA_free(rsa);
    if (pkey)
        EVP_PKEY_free(pkey);
    if (bio_cert)
        BIO_free(bio_cert);

    librdf_world *rdf_world = NULL;
    librdf_storage *rdf_storage = NULL;
    librdf_model *rdf_model = NULL;
    librdf_query *rdf_query = NULL;
    librdf_query_results *rdf_query_results = NULL;

    if (subjAltName != NULL
        && pkey_n != NULL && pkey_e != NULL) {
        ap_log_rerror(APLOG_MARK, APLOG_DEBUG, 0, request, "WebID: subjectAltName = %s", subjAltName);
        ap_log_rerror(APLOG_MARK, APLOG_DEBUG, 0, request, "WebID: client pkey.n  = %s", pkey_n);
        ap_log_rerror(APLOG_MARK, APLOG_DEBUG, 0, request, "WebID: client pkey.e  = %s", pkey_e);

        rdf_world = librdf_new_world();
        if (rdf_world != NULL) {
            librdf_world_open(rdf_world);
            rdf_storage = librdf_new_storage(rdf_world, "uri", subjAltName, NULL);
            if (rdf_storage != NULL) {
                rdf_model = librdf_new_model(rdf_world, rdf_storage, NULL);
            } else
                ap_log_rerror(APLOG_MARK, APLOG_ERR, 0, request, "WebID: librdf_new_storage returned NULL");
        }
        char *c_query = apr_psprintf(request->pool,
            " PREFIX rdf: <http://www.w3.org/1999/02/22-rdf-syntax-ns#>"
            " PREFIX cert: <http://www.w3.org/ns/auth/cert#>"
            " PREFIX rsa: <http://www.w3.org/ns/auth/rsa#>"
            " SELECT ?mod_hex WHERE {"
            " ?key rdf:type rsa:RSAPublicKey."
            " ?key rsa:public_exponent ?exp."
            " ?key rsa:modulus ?mod."
            " ?exp cert:decimal \"%d\"."
            " ?mod cert:hex ?mod_hex."
            " }", apr_strtoi64(pkey_e, NULL, 16));
        ap_log_rerror(APLOG_MARK, APLOG_DEBUG, 0, request, "WebID: query = %s", c_query);

        if (rdf_model != NULL) {
            rdf_query = librdf_new_query(rdf_world, "sparql", NULL, (unsigned char *)c_query, NULL);
        } else
            ap_log_rerror(APLOG_MARK, APLOG_ERR, 0, request, "WebID: librdf_new_query returned NULL");

        if (rdf_query != NULL) {
            rdf_query_results = librdf_query_execute(rdf_query, rdf_model);
            if (rdf_query_results != NULL) {
                if (librdf_query_results_get_count(rdf_query_results) > 0) {
                    librdf_node *rdf_node;
                    unsigned char *mod_hex;
                    while (NULL != (rdf_node = librdf_query_results_get_binding_value_by_name(rdf_query_results, "mod_hex"))) {
                        mod_hex = librdf_node_get_literal_value(rdf_node);
                        ap_log_rerror(APLOG_MARK, APLOG_DEBUG, 0, request, "WebID: modulus = %s", mod_hex);
                        if (matches_pkey(mod_hex, pkey_n)) {
                            r = OK;
                            break;
                        }
                        librdf_free_node(rdf_node);
                        if (librdf_query_results_next(rdf_query_results)) break;
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
    }

    if (conf->authoritative && r != OK) {
        if (subjAltName != NULL) {
            ap_log_rerror(APLOG_MARK, APLOG_INFO | APLOG_TOCLIENT, 0, request, "WebID authentication failed: <%s>. Request URI: %s", subjAltName, request->uri);
        } else {
            ap_log_rerror(APLOG_MARK, APLOG_DEBUG, 0, request, "WebID authentication failed. Request URI: %s", request->uri);
        }
    }
    else if (r == OK) {
        ap_log_rerror(APLOG_MARK, APLOG_DEBUG, 0, request, "WebID authentication succeeded: <%s>. Request URI: %s", subjAltName, request->uri);
        request->user = apr_psprintf(request->connection->pool, "<%s>", subjAltName);
        {
            apr_status_t rv;
            rv = apr_pool_userdata_set(request->user, UD_WEBID_KEY, NULL, request->connection->pool);
            ap_log_rerror(APLOG_MARK, APLOG_DEBUG, rv, request, "set connection cached WebID: %s", request->user);
        }
    }
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
