/*
 * Copyright 2021. Heekuck Oh, all rights reserved
 * 이 프로그램은 한양대학교 ERICA 소프트웨어학부 재학생을 위한 교육용으로 제작되었습니다.
 *
 * 이 코드는 umul_inv() 함수가 올바른지 검증하기 위한 것입니다.
 * 문제의 핵심은 unsigned 64 비트는 경우의 수가 너무 많아서 다 검증하기가 어렵다는 점입니다.
 * 아이디어는 문제의 규모를 64 비트에서 8 비트로 축소해서 모든 경우의 수를 검증하는 것입니다.
 * 8비트 버전이 올바르게 돌아가면 8비트를 64비트로 단순하게 확장하기만 하면 됩니다.
 */
#include <stdio.h>
#include <stdlib.h>

/*
 * gcd() - Euclidean algorithm
 *
 * 유클리드 알고리즘 gcd(a,b) = gcd(b,a mod b)를 사용하여 최대공약수를 계산한다.
 * 만일 a가 0이면 b가 최대공약수가 된다. 그 반대도 마찬가지이다.
 * a, b가 모두 음이 아닌 정수라고 가정한다.
 * 재귀함수 호출을 사용하지 말고 while 루프를 사용하여 구현하는 것이 빠르고 좋다.
 */
int gcd(int a, int b)
{
    int temp;
    
    while (b != 0) {
        temp = a % b;
        a = b;
        b = temp;
    }
    return a;
}

/*
 * 아래는 수업 시간에 설명한 일반적인 알고리즘에서 int -> uint8_t으로 수정한 것입니다.
 * 아래 코드는 문제가 발생합니다. 이 코드를 또는 여러분이 작성한 코드를 *8비트 변수만* 사용하여
 * 문제가 발생하지 않도록 수정할 수 있다면 사실상 올바른 해를 얻은 것입니다. 왜냐하면 이제 8비트
 * 변수를 64비트 변수로 바꾸기만 하면 되니까요.
 */
uint8_t umul_inv8(uint8_t a, uint8_t m)
{
    uint8_t d0=a, d1=m, q;
	int x0=1, x1=0; // 음수를 저장하기 위해 int 타입의 변수 선언

	while(d1 > 1){
        uint8_t tmp_d;
        int tmp_x;
		q = d0/d1;

		d0 = d0 - q*d1; // d0 = d0 % d1
        tmp_d = d1; // SWAP(d0,d1)
        d1 = d0;
        d0 = tmp_d;

		x0 = x0 - (int)q*x1; // x0 = x0 % x1
        tmp_x = x1; // SWAP(x0,x1)
        x1 = x0;
        x0 = tmp_x;
	}

    if(d1 == 1) // 서로소이면
        return (x1 > 0 ? (uint8_t)x1 : m-(uint8_t)(-x1)); //음수이면 양수로 변환하여 반환
    else // 서로소가 아니면 
        return 0; // 역을 구할 수 없으므로 0 반환
}

/*
 * 함수가 올르게 동작하는지 검증하기 위한 메인 함수
 */
int main(void)
{
    int a, m, ai;

    for (m = 2; m < 256; ++m)
        for (a = 2; a < 256; ++a) {
            ai = umul_inv8(a, m);
            if (gcd(a, m) != 1 && ai == 0) continue;
            if ((a*ai) % m != 1) {
                printf("오류: a = %d, ai = %d, m = %d, a*ai mod m = %d, 올바른 역이 아님.\n", a, ai, m, (a*ai) % m);
                exit(1);
            }
        }
    printf("Passed...Congratulations!\n");
    return 0;
}
