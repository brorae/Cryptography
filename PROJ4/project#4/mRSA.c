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

static uint64_t mod_add(uint64_t a, uint64_t b, uint64_t m)
{
    a = a % m;
    b = b % m;
    return (a >= (m-b) ? a-(m-b) : a + b); // (a + b) >= m ? a + b - m : a + b)
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
    uint64_t q, tmp;
    int sign = -1;

    while (d1 > 1)
    {
        q = d0 / d1;

        tmp = d0 - q * d1;
        d0 = d1;
        d1 = tmp;

        tmp = x0 + q * x1;
        x0 = x1;
        x1 = tmp;

        sign = ~sign; //x1값이 while문을 돌 때마다 부호가 바뀜 unsign int를 고려함.
    }
    if (d1 == 1)
        return (sign ? m - x1 : x1); // sign변수를 통해 부호 결정
    else
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
    uint64_t q, k, tmp, isPrime;

    if (n <= 37){    
        for(int i = 0; i < 12; i++){
            if(n == a[i]) return PRIME;
        }
    }

    q = (n - 1);
    k = 0;

    while(q % 2 == 0){
        q = q / 2;
        k++;
    }

    for(int i = 0; i < 12; i++){
        isPrime = COMPOSITE;
        if(mod_pow(a[i], q, n) == 1) isPrime = PRIME;
        else{
            for(int j = 0; j < k; j++){
                if(j==0) tmp = mod_pow(a[i],q,n);
                else tmp = mod_mul(tmp,tmp,n);
                if(tmp == n-1) isPrime = PRIME;
            }
        }
        if(isPrime == COMPOSITE) return COMPOSITE;
    }
    return isPrime;
}

/*
 * mRSA_generate_key() - generates mini RSA keys e, d and n
 * Carmichael's totient function Lambda(n) is used.
 */
void mRSA_generate_key(uint64_t *e, uint64_t *d, uint64_t *n)
{
    uint64_t p, q, tmp=0, bit=1;
    uint64_t lambda = 0;

    bit = (bit<<31) + 1;

    while (tmp < MINIMUM_N) // p, q 랜덤 선택
    {
        do{
            p =  bit | arc4random();
        } while (miller_rabin(p)==COMPOSITE);

        do{
            q =  bit |arc4random();
        } while (miller_rabin(q)==COMPOSITE);
        
        tmp = p * q;
    }
    *n = tmp; // n 생성
    lambda = (p-1)*(q-1)/gcd(p-1,q-1);

    do{
        tmp = arc4random_uniform(lambda);
    } while (gcd(tmp,lambda) != 1 || tmp <=1); // e, d 생성
    *e = tmp;
    *d = mul_inv(*e,lambda);
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