/**
 * @file    test_bignum_mul_bignum_runner.c
 * @author  git@bayborodov.com
 * @version 1.0.0
 * @date    03.12.2025
 *
 * @brief Интеграционный тест‑раннер для библиотеки libbignum_mul_bignum.a.
 * @details Применяется для проверки достаточности сигнатур 
 *          в файле заголовка (header) при сборке и линковке
 *          статической библиотеки libbignum_mul_bignum.a
 *
 * @history
 *   - rev. 1 (03.12.2025): Создание теста
 */  
#include "bignum_mul_bignum.h"
#include <assert.h>
#include <stdio.h>  
int main() {
 printf("Running test: test_bignum_mul_bignum_runner... "); 
 bignum_t res = {0}; 
 bignum_t a = {0}; 
 bignum_t b = {0}; 			
 bignum_mul_bignum(&res, &a, &b);
 assert(1);
 printf("PASSED\n");   
 return 0;  
}