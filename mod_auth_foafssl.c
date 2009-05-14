/* mod_auth_foafssl
 * FOAF+SSL authentication module for Apache 2
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

static APR_OPTIONAL_FN_TYPE(ssl_var_lookup) *ssl_var_lookup;
static APR_OPTIONAL_FN_TYPE(ssl_ext_lookup) *ssl_ext_lookup;

typedef struct {
    int authoritative;
} auth_foafssl_config_rec;

static void *
create_auth_foafssl_dir_config(apr_pool_t *p, char *dirspec) {
    auth_foafssl_config_rec *conf = apr_pcalloc(p, sizeof(*conf));

    conf->authoritative = -1;
    return conf;
}

static void *
merge_auth_foafssl_dir_config(apr_pool_t *p, void *parent_conf, void *newloc_conf) {
    auth_foafssl_config_rec *pconf = parent_conf, *nconf = newloc_conf,
    *conf = apr_pcalloc(p, sizeof(*conf));

    conf->authoritative = (nconf->authoritative != -1) ?
        nconf->authoritative : pconf->authoritative;
    return conf;
}

static const command_rec
auth_foafssl_cmds[] = {
    AP_INIT_FLAG("AuthFOAFSSLAuthoritative", ap_set_flag_slot,
                 (void *)APR_OFFSETOF(auth_foafssl_config_rec, authoritative),
                 OR_AUTHCFG,
                 "Set to 'Off' to allow access control to be passed along to "
                 "lower modules if the WebID is not known to this module"),
    {NULL}
};

module AP_MODULE_DECLARE_DATA auth_foafssl_module;

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
foaf_matches_pkey(unsigned char *foaf, char *pkey) {
    if (foaf == NULL || pkey == NULL)
        return 0;
    unsigned int s_foaf = strlen(foaf);
    unsigned int s_pkey = strlen(pkey);
    unsigned int fc, pc, j, k = 0;

    for (j = 0; j < s_foaf; j++) {
        if ((fc = hex_or_x(foaf[j])) == 'x')
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
authenticate_foafssl_user(request_rec *request) {
    int r = 0;
    auth_foafssl_config_rec *conf =
        ap_get_module_config(request->per_dir_config, &auth_foafssl_module);
    if (!conf->authoritative) r = DECLINED;
    else r = HTTP_UNAUTHORIZED;

    /* Check for AuthType FOAFSSL */
    const char *current_auth = ap_auth_type(request);
    if (!current_auth || strcasecmp(current_auth, "FOAFSSL") != 0) {
        return DECLINED;
    }
    request->ap_auth_type = "FOAFSSL";

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
        ap_log_rerror(APLOG_MARK, APLOG_DEBUG, 0, request, "FOAFSSL: invalid client certificate");
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
        ap_log_rerror(APLOG_MARK, APLOG_DEBUG, 0, request, "FOAFSSL: subjectAltName = %s", subjAltName);
        ap_log_rerror(APLOG_MARK, APLOG_DEBUG, 0, request, "FOAFSSL: client pkey.n  = %s", pkey_n);
        ap_log_rerror(APLOG_MARK, APLOG_DEBUG, 0, request, "FOAFSSL: client pkey.e  = %s", pkey_e);

        rdf_world = librdf_new_world();
        if (rdf_world != NULL) {
            librdf_world_open(rdf_world);
            rdf_storage = librdf_new_storage(rdf_world, "uri", subjAltName, NULL);
        }
        if (rdf_storage != NULL) rdf_model = librdf_new_model(rdf_world, rdf_storage, NULL);
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
        ap_log_rerror(APLOG_MARK, APLOG_DEBUG, 0, request, "FOAFSSL: query = %s", c_query);
        if (rdf_model != NULL) rdf_query = librdf_new_query(rdf_world, "sparql", NULL, (unsigned char *)c_query, NULL);

        if (rdf_query != NULL) {
            rdf_query_results = librdf_query_execute(rdf_query, rdf_model);
            if (rdf_query_results != NULL) {
                if (librdf_query_results_get_count(rdf_query_results) > 0) {
                    librdf_node *rdf_node;
                    unsigned char *mod_hex;
                    while (NULL != (rdf_node = librdf_query_results_get_binding_value_by_name(rdf_query_results, "mod_hex"))) {
                        mod_hex = librdf_node_get_literal_value(rdf_node);
                        ap_log_rerror(APLOG_MARK, APLOG_DEBUG, 0, request, "FOAFSSL: modulus = %s", mod_hex);
                        if (foaf_matches_pkey(mod_hex, pkey_n)) {
                            request->user = apr_psprintf(request->pool, "<%s>", subjAltName);
                            r = OK;
                            break;
                        }
                        librdf_free_node(rdf_node);
                        if (librdf_query_results_next(rdf_query_results)) break;
                    }
                }
                librdf_free_query_results(rdf_query_results);
            } else
                ap_log_rerror(APLOG_MARK, APLOG_ERR, 0, request, "FOAFSSL: librdf_query_execute returned NULL");
            librdf_free_query(rdf_query);
        } else
            ap_log_rerror(APLOG_MARK, APLOG_ERR, 0, request, "FOAFSSL: librdf_new_query returned NULL");

        if (rdf_model) librdf_free_model(rdf_model);
        if (rdf_storage) librdf_free_storage(rdf_storage);
        if (rdf_world) librdf_free_world(rdf_world);
    }

    if (conf->authoritative && r != OK) {
        if (subjAltName != NULL) {
            ap_log_rerror(APLOG_MARK, APLOG_INFO | APLOG_TOCLIENT, 0, request, "FOAFSSL client authentication failed, FOAF URI: <%s>", subjAltName);
        } else {
            ap_log_rerror(APLOG_MARK, APLOG_DEBUG, 0, request, "FOAFSSL client authentication failed, local URI: %s", request->uri);
        }
    }
    else if (r == OK)
        ap_log_rerror(APLOG_MARK, APLOG_DEBUG, 0, request, "FOAFSSL client authentication succeeded, FOAF URI: <%s>, local URI: %s", subjAltName, request->uri);
    return r;
}

static void
import_ssl_func() {
    ssl_var_lookup = APR_RETRIEVE_OPTIONAL_FN(ssl_var_lookup);
    ssl_ext_lookup = APR_RETRIEVE_OPTIONAL_FN(ssl_ext_lookup);
}

static void
register_hooks(apr_pool_t *p) {
    ap_hook_check_user_id(authenticate_foafssl_user, NULL, NULL, APR_HOOK_MIDDLE);
    ap_hook_optional_fn_retrieve(import_ssl_func, NULL, NULL, APR_HOOK_MIDDLE);
}

module AP_MODULE_DECLARE_DATA
auth_foafssl_module = {
    STANDARD20_MODULE_STUFF,
    create_auth_foafssl_dir_config,  /* dir config creater */
    merge_auth_foafssl_dir_config,   /* dir merger */
    NULL,                            /* server config */
    NULL,                            /* merge server config */
    auth_foafssl_cmds,               /* command apr_table_t */
    register_hooks                   /* register hooks */
};
