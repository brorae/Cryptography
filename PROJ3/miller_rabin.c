/*
 * Copyright 2020, 2021. Heekuck Oh, all rights reserved
 * 이 프로그램은 한양대학교 ERICA 소프트웨어학부 재학생을 위한 교육용으로 제작되었습니다.
 */
#include "miller_rabin.h"

/*
 * Miller-Rabin Primality Testing against small sets of bases
 *
 * if n < 2^64,
 * it is enough to test a = 2, 3, 5, 7, 11, 13, 17, 19, 23, 29, 31, and 37.
 *
 * if n < 3,317,044,064,679,887,385,961,981,
 * it is enough to test a = 2, 3, 5, 7, 11, 13, 17, 19, 23, 29, 31, 37, and 41.
 */
const uint64_t a[ALEN] = {2,3,5,7,11,13,17,19,23,29,31,37};

/*
 * miller_rabin() - Miller-Rabin Primality Test (deterministic version)
 *
 * n > 3, an odd integer to be tested for primality
 * It returns 1 if n is prime, 0 otherwise.
 */
int miller_rabin(uint64_t n)
{
    uint64_t k,q;
    for (int i=0;i<ALEN;i++){
        if (n == a[i]) return PRIME;
    }
    q = n-1;
    k = 0;
    while(k%2 == 0){
        q /= 2;
        k += 1;
    }
    int ans;
    for (int i=0;i<ALEN;i++){
        ans = COMPOSITE;
        if (mod_pow(a[i],q,n) == 1) ans = PRIME;
        int l=1;
        for (uint64_t j=0;j<k;j++){
            if (mod_pow(mod_pow(a[i],q,n),l,n) == n-1) ans = PRIME;
            l *= 2;
        }
        if(ans == COMPOSITE) return COMPOSITE;
    }
    return ans;
}
