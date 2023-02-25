#include <fcntl.h>
#include <stdint.h>
#include <stdio.h>
#include <unistd.h>

#include <openssl/bn.h>
#include <openssl/ecdh.h>
#include <openssl/evp.h>

#include "libkmem/base64.h"
#include "libkmem/buf.h"
#include "libkmem/list.h"
#include "words.h"

static int ecdh_generate_secret(const struct buf *my_priv_key,
                                const struct buf *his_pub_key,
                                struct buf **secret)
{
    EC_KEY *ecdh = NULL;
    BN_CTX *bn_ctx = NULL;
    EC_POINT *pub_key_ec_point = NULL;
    BIGNUM *bignum_priv_key = NULL;
    size_t secret_len;
    int rc = -1;

    ecdh = EC_KEY_new_by_curve_name(NID_X9_62_prime256v1);
    if (!ecdh)
        goto out;

    bignum_priv_key = BN_bin2bn(my_priv_key->data, buf_len(my_priv_key), NULL);
    if (!bignum_priv_key)
        goto out;

    rc = EC_KEY_set_private_key(ecdh, bignum_priv_key);
    if (rc != 1)
        goto out;


    bn_ctx = BN_CTX_new();
    if (!bn_ctx)
        goto out;

    pub_key_ec_point = EC_POINT_new(EC_KEY_get0_group(ecdh));
    if (!pub_key_ec_point)
        goto out;


    rc = EC_POINT_oct2point(EC_KEY_get0_group(ecdh), pub_key_ec_point,
                            his_pub_key->data, buf_len(his_pub_key), bn_ctx);
    if (rc != 1)
        goto out;

    secret_len = (EC_GROUP_get_degree(EC_KEY_get0_group(ecdh)) + 7) / 8;
    *secret = buf_alloc(secret_len);
    secret_len = ECDH_compute_key((*secret)->data, secret_len,
                                    pub_key_ec_point, ecdh, NULL);
    buf_put(*secret, secret_len);
    rc = 0;
out:
    if (ecdh)
        EC_KEY_free(ecdh);
    if (pub_key_ec_point)
        EC_POINT_free(pub_key_ec_point);
    if (bn_ctx)
        BN_CTX_free(bn_ctx);
    if (bignum_priv_key)
        BN_free(bignum_priv_key);
    return rc;
}

int file_put_contents(const char *filename, const struct buf *buf) 
{
    int fd = -1;
    const u8 *p = buf->data;
    size_t left_to_write = buf_len(buf);
    off_t offset = 0;

    fd = open(filename, O_CREAT | O_WRONLY, 0777);
    if (fd < 3) {
        fprintf(stderr, "Can't open file %s for write\n", filename);
        return -1;
    }

    do {
        long long int bytes_written = pwrite(fd, p + offset, left_to_write, offset);
        if (bytes_written < 0) {
            fprintf(stderr, "write error in file %s\n", filename);
            close(fd);
            return -1;
        }
        offset += bytes_written;
        left_to_write -= bytes_written;
    } while (left_to_write);

    close(fd);
    return 0;
}

struct buf *aes256gcm_decrypt(const struct buf *src, const struct buf *iv,
                              const struct buf *key)
{
  EVP_CIPHER_CTX *ctx = NULL;
  int rc = 0, len = 0;
  struct buf *dst = NULL;

  dst = buf_alloc(buf_len(src) - 16);
  if (!dst) {
    fprintf(stderr, "Can't allocate destination buf\n");
    goto out;
  }

  ctx = EVP_CIPHER_CTX_new();
  if (!ctx) {
    fprintf(stderr, "Can't create context\n");
    goto out;
  }
  EVP_CIPHER_CTX_init(ctx);

  rc = EVP_DecryptInit_ex(ctx, EVP_aes_256_gcm(), NULL, NULL, NULL);
  if (rc != 1) {
    fprintf(stderr, "Can't init EVP_aes_256_gcm\n");
    goto out;
  }
  if (!EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_SET_IVLEN, 16, NULL)) {
    fprintf(stderr, "Can't set IVLEN\n");
    goto out;
  }
  if (!EVP_DecryptInit_ex(ctx, NULL, NULL, key->data, iv->data)) {
    fprintf(stderr, "Can't set KEY and IV\n");
    goto out;
  }
  rc = EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_SET_TAG, 16,
                           src->data + buf_len(dst));
  if (rc != 1) {
    fprintf(stderr, "Can't set TAG\n");
    goto out;
  }
  rc = EVP_DecryptUpdate(ctx, dst->data, &len, src->data, buf_len(dst));
  if (rc != 1) {
    fprintf(stderr, "Can't decrypt update\n");
    goto out;
  }
  rc = EVP_DecryptFinal_ex(ctx, dst->data + len, &len);
  if (rc != 1) {
    rc = -2;
    fprintf(stderr, "can't finalize decrypt\n");
    goto out;
  }
  buf_ref(dst);
out:
  if (ctx)
    EVP_CIPHER_CTX_free(ctx);
  buf_deref(&dst);
  
  return dst;
}

int main(int argc, char *argv[])
{
    (void)argc;
    (void)argv;
    struct buf *rawMnemonics = NULL;
    struct list *mnemonics = NULL;
    struct buf *privKey = NULL;
    struct buf *rawSecrets = NULL;
    struct list *secrets = NULL;
    struct list *decryptedSecrets = NULL;
    struct buf *joinedDecryptedSecrets = NULL;

    int rc = -1;
    rawMnemonics = file_get_contents("priv");
    if (!rawMnemonics) {
        fprintf(stderr, "Can't read priv\n");
        goto out;
    }
    buf_put(rawMnemonics, buf_len(rawMnemonics) - 1); // remove \n
    mnemonics = buf_split(rawMnemonics, ' ');
    if (!mnemonics) {
        fprintf(stderr, "Can't split rawMnemonics\n");
        goto out;
    }

    privKey = mnemonicToPrivKey(mnemonics);
    if (!privKey) {
        fprintf(stderr, "Can't obtain private key\n");
        goto out;
    }

    rawSecrets = file_get_contents("secrets");
    if (!rawSecrets) {
        fprintf(stderr, "Can't read secrets\n");
        goto out;
    }
    buf_put(rawSecrets, buf_len(rawSecrets) - 1); // remove last \n
    secrets = buf_split(rawSecrets, '\n');
    if (!secrets) {
        fprintf(stderr, "Can't split secrets\n");
        goto out;
    }

    decryptedSecrets = list_create();
    if (!decryptedSecrets) {
        fprintf(stderr, "Can't create decryptedSecrets\n");
        goto out;
    }
    list_init(decryptedSecrets);

    struct le *le;
    struct list *secretParts = NULL;
    struct buf *encryptedData = NULL;
    struct buf *iv = NULL;
    struct buf *pubKeyDer = NULL;
    struct buf *pubKey = NULL;
    struct buf *aesKey = NULL;
    struct buf *decryptedData = NULL;
    LIST_FOREACH(secrets, le) {
        kmem_deref(&secretParts);
        kmem_deref(&encryptedData);
        kmem_deref(&iv);
        kmem_deref(&pubKeyDer);
        kmem_deref(&pubKey);
        kmem_deref(&aesKey);
        kmem_deref(&decryptedData);
        
        struct buf *secret = (struct buf *)list_ledata(le);
        secretParts = buf_split(secret, '.');
        if (!secretParts) {
            fprintf(stderr, "Can't split secret:");
            buf_dump(secret);
            continue;
        }
        if (list_count(secretParts) != 3) {
            fprintf(stderr, "Invalid secret:");
            buf_dump(secret);
            continue;
        }

        struct le *secretLe = list_head(secretParts);
        encryptedData = base64_decode((struct buf *)list_ledata(secretLe));
        if (!encryptedData) {
            fprintf(stderr, "Can't decode encrypted data and tag in");
            buf_dump(secret);
            continue;
        }

        iv = base64_decode((struct buf *)list_ledata(secretLe = le_next(secretLe)));
        if (!iv) {
            fprintf(stderr, "Can't decode iv in");
            buf_dump(secret);
            continue;
        }

        pubKeyDer = base64_decode((struct buf *)list_ledata(le_next(secretLe)));
        if (!pubKeyDer) {
            fprintf(stderr, "Can't decode pubkey DER in");
            buf_dump(secret);
            continue;
        }
        pubKey = buf_cpy(pubKeyDer->data + 26, 65);
        if (!pubKey) {
            fprintf(stderr, "Can't strip pubkey from");
            buf_dump(secret);
            continue;
        }
        rc = ecdh_generate_secret(privKey, pubKey, &aesKey);
        if (rc) {
            fprintf(stderr, "Can't create AES key for");
            buf_dump(secret);
            continue;
        }

        decryptedData = aes256gcm_decrypt(encryptedData, iv, aesKey);
        if (!decryptedData) {
            fprintf(stderr, "Can't decrypt data for");
            buf_dump(secret);
            continue;
        }
        buf_ref(decryptedData);
        buf_list_append(decryptedSecrets, decryptedData);
    }

    kmem_deref(&secretParts);
    kmem_deref(&encryptedData);
    kmem_deref(&iv);
    kmem_deref(&pubKeyDer);
    kmem_deref(&pubKey);
    kmem_deref(&aesKey);
    kmem_deref(&decryptedData);

    joinedDecryptedSecrets = buf_list_join(decryptedSecrets, '\n');
    if (!joinedDecryptedSecrets) {
        fprintf(stderr, "Can't join decrypted secrets, dumping them here:");
        buf_list_dump(decryptedSecrets);
        goto out;
    }
    if (file_put_contents("decryptedSecrets", joinedDecryptedSecrets)) {
        fprintf(stderr, "Can't write decrypted secrets, dumping them here:");
        buf_list_dump(decryptedSecrets);
        goto out;
    }

    rc = 0;
out:
    kmem_deref(&joinedDecryptedSecrets);
    kmem_deref(&decryptedSecrets);
    kmem_deref(&rawMnemonics);
    kmem_deref(&mnemonics);
    kmem_deref(&privKey);
    kmem_deref(&rawSecrets);
    kmem_deref(&secrets);
    kmem_deref(&decryptedSecrets);
    kmem_deref(&joinedDecryptedSecrets);

    return rc;
}
