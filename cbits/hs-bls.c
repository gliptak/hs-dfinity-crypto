#define MCLBN_FP_UNIT_SIZE 6
#include <bls/bls.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <assert.h>

#define IN(t, x, s, n) \
  bls ## t x[1]; \
  bls ## t ## Deserialize(x, s, n)

#define OUT(t, x, out) \
  enum { bufsz = 64 }; \
  bls ## t ## Serialize(out, bufsz, x); \
  return

void shimInit() { blsInit(0, MCLBN_FP_UNIT_SIZE); }

void frmapnew(char *s, int slen, char *out) {
  blsSecretKey x[1];
  blsHashToSecretKey(x, s, slen);
  OUT(SecretKey, x, out);
}

void fromSecretNew(char *s, int slen, char *out) {
  IN(SecretKey, x, s, slen);
  blsPublicKey gx[1];
  blsGetPublicKey(gx, x);
  OUT(PublicKey, gx, out);
}

void blsSignatureNew(char *s, int slen, char* m, int mlen, char *out) {
  IN(SecretKey, x, s, slen);
  blsSignature sig[1];
  blsSign(sig, x, m, mlen);
  OUT(Signature, sig, out);
}

void shimSign(char *s, int slen, char *m, int mlen, char *out) {
  IN(SecretKey, x, s, slen);
  blsSignature sig[1];
  blsSign(sig, x, m, mlen);
  OUT(Signature, sig, out);
}

int shimVerify(char *s, int slen, char *t, int tlen, char *m, int mlen) {
  IN(Signature, hx, s, slen);
  IN(PublicKey, gx, t, tlen);
  return blsVerify(hx, gx, m, mlen);
}

void getPopNew(char* t, int tlen, char *out) {
  IN(SecretKey, x, t, tlen);
  blsSignature sig[1];
  blsGetPop(sig, x);
  OUT(Signature, sig, out);
}

int shimVerifyPop(char *s, int slen, char *t, int tlen) {
  IN(Signature, sig, s, slen);
  IN(PublicKey, pub, t, tlen);
  return blsVerifyPop(sig, pub);
}

struct dkg {
  int t;
  blsPublicKey gpk[1];
  blsPublicKey *pk;
  blsSecretKey *sk;
};

void *dkgNew(int t) {
  struct dkg* r = malloc(sizeof(struct dkg));
  r->pk = malloc(sizeof(blsPublicKey) * t);
  r->sk = malloc(sizeof(blsSecretKey) * t);
  r->t = t;
  int i;
  for (i = 0; i < t; i++) {
    blsSecretKeySetByCSPRNG(r->sk + i);
    blsGetPublicKey(r->pk + i, r->sk + i);
  }
  blsId id0[1];
  blsIdSetInt(id0, 0);
  blsPublicKeyShare(r->gpk, r->pk, t, id0);
  return r;
}

void dkgFree(struct dkg* r) {
  free(r->pk);
  free(r->sk);
  free(r);
}

void dkgPublicKeyNew(struct dkg* p, int i, char *out) {
  assert(0 <= i && i < p->t);
  OUT(PublicKey, p->pk + i, out);
}

void dkgSecretShareNewWithId(struct dkg* p, int i, char *out) {
  if (!i) {
    fprintf(stderr, "BUG: ID = 0\n");
    exit(1);
  }
  blsId id[1];
  blsIdSetInt(id, i);
  blsSecretKey sh[1];
  blsSecretKeyShare(sh, p->sk, p->t, id);
  OUT(SecretKey, sh, out);
}

void dkgSecretShareNew(struct dkg* p, char* s, int slen, char *out) {
  blsId id[1];
  blsIdDeserialize(id, s, slen);
  blsSecretKey sh[1];
  blsSecretKeyShare(sh, p->sk, p->t, id);
  OUT(SecretKey, sh, out);
}

void dkgPublicShareNew(void** ptr, int* ptrlen, int t, char *s, int slen, char *out) {
  blsPublicKey *pks = malloc(sizeof(blsPublicKey) * t);
  for (int i = 0; i < t; i ++) {
    blsPublicKeyDeserialize(pks + i, ptr[i], ptrlen[i]);
  }
  blsPublicKey pk[1];
  blsId id[1];
  blsIdDeserialize(id, s, slen);
  blsPublicKeyShare(pk, pks, t, id);
  free(pks);
  OUT(PublicKey, pk, out);
}

void dkgGroupPublicKeyNew(struct dkg* p, char *out) {
  OUT(PublicKey, p->gpk, out);
}

struct sigshare {
  int t;
  int i;
  blsSignature *sig;
  blsId *id;
};

void *signatureShareNew(int t) {
  struct sigshare *r = malloc(sizeof(struct sigshare));
  r->t = t;
  r->i = 0;
  r->sig = malloc(sizeof(blsSignature) * t);
  r->id = malloc(sizeof(blsId) * t);
  return r;
}

void signatureShareFree(struct sigshare *p) {
  free(p->sig);
  free(p->id);
  free(p);
}

void signatureShareAddWithId(struct sigshare *p, int i, char *sig, int siglen) {
  if (p->i == p->t) {
    fprintf(stderr, "BUG: too many signature shares\n");
    exit(1);
  }
  blsSignatureDeserialize(p->sig + p->i, sig, siglen);
  blsIdSetInt(p->id + p->i, i);
  p->i++;
}

void signatureShareAdd(struct sigshare *p, char *id, int idlen, char *sig, int siglen) {
  if (p->i == p->t) {
    fprintf(stderr, "BUG: too many signature shares\n");
    exit(1);
  }
  blsSignatureDeserialize(p->sig + p->i, sig, siglen);
  blsIdDeserialize(p->id + p->i, id, idlen);
  p->i++;
}

void recoverSignatureNew(struct sigshare *p, char *out) {
  if (p->i != p->t) {
    fprintf(stderr, "BUG: too few signature shares\n");
    exit(1);
  }
  blsSignature sig[1];
  blsSignatureRecover(sig, p->sig, p->id, p->t);
  OUT(Signature, sig, out);
}

void secretKeyAdd(char *s, int slen, char *t, int tlen, char *out) {
  IN(SecretKey, x, s, slen);
  IN(SecretKey, y, t, tlen);
  blsSecretKeyAdd(x, y);
  OUT(SecretKey, x, out);
}

void publicKeyAdd(char *s, int slen, char *t, int tlen, char *out) {
  IN(PublicKey, x, s, slen);
  IN(PublicKey, y, t, tlen);
  blsPublicKeyAdd(x, y);
  OUT(PublicKey, x, out);
}
