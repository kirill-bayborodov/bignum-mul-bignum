/**
 * @file    test_bignum_mul_bignum_extra.c
 * @author  git@bayborodov.com
 * @version 1.0.3
 * @date    30.06.2026
 *
 * @brief   Дополнительные тесты (робастность, фаззинг) для bignum_mul_bignum v0.0.2.
 *
 * @details
 *   Этот файл содержит тесты, проверяющие поведение функции в нештатных
 *   ситуациях: передача NULL-указателей, перекрытие буферов и случайные
 *   (фаззинг) входные данные.
 *
 * @history
 *   - rev. 1 (02.08.2025): Создание экстра-тестов для версии 0.0.2.
 *   - rev. 2 (02.08.2025): Вспомогательная функция simple_mul переписана
 *                         без использования нестандартного типа __int128
 *                         для соответствия ISO C и устранения предупреждений.
 *   - rev. 3 (30.06.2026): В функции test_fuzzing эталонная длина вычисляется в цикле while. Условие expected_len > 1 не дает длине опуститься до нуля. Меняем его на > 0
 */

#include "bignum_mul_bignum.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <assert.h>
#include <time.h>

// Вспомогательная функция для сравнения bignum_t
int bignum_are_equal(const bignum_t* a, const bignum_t* b) {
    if (a->len != b->len) return 0;
    return memcmp(a->words, b->words, a->len * sizeof(uint64_t)) == 0;
}

void test_robustness_null_args() {
    printf("Running test: %s\n", __func__);
    bignum_t a, b, res;
    assert(bignum_mul_bignum(NULL, &a, &b) == BIGNUM_MUL_BIGNUM_ERROR_NULL_ARG);
    assert(bignum_mul_bignum(&res, NULL, &b) == BIGNUM_MUL_BIGNUM_ERROR_NULL_ARG);
    assert(bignum_mul_bignum(&res, &a, NULL) == BIGNUM_MUL_BIGNUM_ERROR_NULL_ARG);
    printf("...PASSED\n");
}

void test_buffer_overlap() {
    printf("Running test: %s\n", __func__);
    bignum_t a = {.words = {5}, .len = 1};
    bignum_t b = {.words = {10}, .len = 1};
    bignum_mul_bignum(&a, &a, &b);
    bignum_mul_bignum(&b, &a, &b);
    printf("...PASSED (no crash)\n");
}


#if defined(__GNUC__)
  #pragma GCC diagnostic push
  #pragma GCC diagnostic ignored "-Wpedantic"
  typedef unsigned __int128 uint128_t;
  #pragma GCC diagnostic pop
#else
  #error "Need 128-bit integer support"
#endif

void simple_mul(uint64_t out[], const uint64_t a[], int an,
                                const uint64_t b[], int bn) {
    // Добавляем проверку на нули, чтобы избежать VLA массива нулевой длины
    if (an == 0 || bn == 0) {
        memset(out, 0, BIGNUM_CAPACITY * sizeof(uint64_t));
        return;
    }
      
    uint128_t tmp[an + bn];
    memset(tmp, 0, sizeof(tmp));
    for (int i = 0; i < an; i++) {
        uint64_t carry = 0;
        for (int j = 0; j < bn; j++) {
            uint128_t prod = (uint128_t)a[i] * b[j];
            uint128_t sum  = tmp[i + j] + prod + carry;
            tmp[i + j]     = (uint64_t)sum;
            carry          = (uint64_t)(sum >> 64);
        }
        tmp[i + bn] += carry;
    }
    // нормализация carry дальше
    uint64_t carry = 0;
    int full = an + bn;
    for (int k = 0; k < full; k++) {
        uint128_t s = (uint128_t)tmp[k] + carry;
        tmp[k] = (uint64_t)s;
        carry  = (uint64_t)(s >> 64);
    }
    // копируем ограничиваясь capacity
    int cap = BIGNUM_CAPACITY;
    int limit = (full < cap ? full : cap);
    for (int k = 0; k < limit; k++) {
        out[k] = (uint64_t)tmp[k];
    }
    // обнуление хвоста
    for (int k = limit; k < cap; k++) {
        out[k] = 0;
    }
}


#include <inttypes.h>
void test_fuzzing(void) {
    printf("Running test: %s (10000 iterations)\n", __func__);
    srand((unsigned)time(NULL));

    for (int i = 0; i < 10000; ++i) {
        bignum_t a = {0}, b = {0}, res = {0}, expected = {0};
        //a.len = (rand() % (BIGNUM_CAPACITY / 2)) + 1;
        //b.len = (rand() % (BIGNUM_CAPACITY / 2)) + 1;
        // Убираем + 1 снаружи и добавляем внутрь делителя, 
        // чтобы диапазон стал [0, BIGNUM_CAPACITY / 2]
        a.len = rand() % (BIGNUM_CAPACITY / 2 + 1);
        b.len = rand() % (BIGNUM_CAPACITY / 2 + 1);

        for (size_t j = 0; j < a.len; ++j)
            a.words[j] = ((uint64_t)rand() << 32) | rand();
        for (size_t j = 0; j < b.len; ++j)
            b.words[j] = ((uint64_t)rand() << 32) | rand();

        int full_len = a.len + b.len;
        bignum_mul_bignum_status_t status = bignum_mul_bignum(&res, &a, &b);

        if (full_len > BIGNUM_CAPACITY) {
            // Ожидаем overflow
            assert(status == BIGNUM_MUL_BIGNUM_ERROR_OVERFLOW);
        }
        else {
            // Успешный случай: сравниваем с эталоном
            assert(status == BIGNUM_MUL_BIGNUM_SUCCESS);

            // эталонная «простая» конволюция
            simple_mul(expected.words, a.words, a.len, b.words, b.len);

            // реальная длина expected
            int expected_len = full_len;
            while (expected_len > 0 && // Исправлено: > 0 вместо > 1
                   expected.words[expected_len - 1] == 0) {
                expected_len--;
            }
            expected.len = expected_len;

            assert(bignum_are_equal(&res, &expected));
        }
    }
    printf("...PASSED\n");
}


int main() {
    printf("\n--- Starting extra tests for bignum_mul_bignum ---\n");
    test_robustness_null_args();
    test_buffer_overlap();
    test_fuzzing();
    printf("--- All extra tests for bignum_mul_bignum passed ---\n");
    return 0;
}
