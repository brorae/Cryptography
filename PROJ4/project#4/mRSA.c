/*
 * Copyright 2020, 2021. Heekuck Oh, all rights reserved
 * 이 프로그램은 한양대학교 ERICA 소프트웨어학부 재학생을 위한 교육용으로 제작되었습니다.
 */
#include <stdlib.h>
#include "mRSA.h"

static uint64_t gcd(uint64_t a, uint64_t b)
{
    uint64_t tmp;
    while(b != 0){
        tmp = a % b;
        a = b;
        b = tmp;
    }
    return a;
}

static uint64_t mod_sub(uint64_t a, uint64_t b, uint64_t m)
{
    a = a % m;
    b = b % m;
    if(a < b) return ((a % m) - (b % m) + m) % m;
    return ((a % m) - (b % m)) % m;
}

static uint64_t mod_add(uint64_t a, uint64_t b, uint64_t m)
{
    a = a % m;
    b = b % m;
    if(a + b < b) return ((a % m) + (b % m) - m) % m;
    return ((a % m) + (b % m)) % m;
}

static uint64_t mod_mul(uint64_t a, uint64_t b, uint64_t m)
{
    uint64_t r = 0;
    while (b > 0) {
        if (b & 1)
            r = mod_add(r, a, m);
        b = b >> 1;
        a = mod_add(a, a, m);
    }
    return r;
}

static uint64_t mul_inv(uint64_t a, uint64_t m)
{
    uint64_t d0 = a, d1 = m;
    uint64_t x0 = 1, x1 = 0;
    uint64_t q = 0, tmp;

    while(d1 > 1){
        q = d0 / d1;

        tmp = mod_sub(d0 ,mod_mul(q, d1, m), m);
        d0 = d1;
        d1 = tmp;

        tmp = mod_sub(x0, mod_mul(q, x1, m), m);
        x0 = x1;
        x1 = tmp;
    }

    if(d1 == 1) return (x1 > 0 ? x1 : x1 + m);
    
    return 0;
}

static uint64_t mod_pow(uint64_t a, uint64_t b, uint64_t m)
{
    uint64_t r = 1;
    while (b > 0) {
        if (b & 1)
            r = mod_mul(r, a, m);
        b = b >> 1;
        a = mod_mul(a, a, m);
    }
    return r;
}

static int miller_rabin(uint64_t n)
{
    uint64_t a[12] = {2, 3, 5, 7, 11, 13, 17, 19, 23, 29, 31, 37};
    uint64_t i, j, q, k, l, flg;

    for(i = 0; i < 12; i++){
        if(n == a[i]) return PRIME;
    }

    q = (n - 1);
    k = 0;

    while(k % 2 == 0){
        q = q / 2;
        k = k + 1;
    }

    for(i = 0; i < 12; i++){
        flg = COMPOSITE;
        if(mod_pow(a[i], q, n) == 1) flg = PRIME;
        l = 1;
        for(j = 0; j < k; j++){
            if(mod_pow(mod_pow(a[i], q, n),l, n) == n-1){
                flg = PRIME;
            }
            l *= 2;
        }
        if(flg == COMPOSITE) return COMPOSITE;
    }
    return flg;
}

/*
 * mRSA_generate_key() - generates mini RSA keys e, d and n
 * Carmichael's totient function Lambda(n) is used.
 */
void mRSA_generate_key(uint64_t *e, uint64_t *d, uint64_t *n)
{
    uint64_t p = 0;
    uint64_t q = 0;
    uint64_t Lambda = 0;

    while (p * q < MINIMUM_N) // p, q 랜덤 선택
    {
        while (1)
        {
            arc4random_buf(&p, sizeof(uint32_t));
            if (p%2==0) continue;
            if (miller_rabin(p)) break;
        }

        while (1)
        {
            arc4random_buf(&q, sizeof(uint32_t));
            if (q%2==0) continue;
            if (miller_rabin(q)) break;
        }
    }
    *n = p * q; // n 생성
    Lambda = (p-1)*(q-1)/gcd(p-1,q-1);

    while (1) // e, d 생성
    {
        arc4random_buf(e,sizeof(uint64_t));
        if ((1 < *e) && (*e < Lambda) && (gcd(*e,Lambda) == 1))
        {
            *d = mul_inv(*e,Lambda);
            break;
        }   
    }
    
}

/*
 * mRSA_cipher() - compute m^k mod n
 * If data >= n then returns 1 (error), otherwise 0 (success).
 */
int mRSA_cipher(uint64_t *m, uint64_t k, uint64_t n)
{
    if(*m >= n) return 1;
    *m = mod_pow(*m, k, n);
    return 0;
}
