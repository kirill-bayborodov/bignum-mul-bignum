/**
 * @file    test_bignum_mul_bignum.c
 * @author  git@bayborodov.com
 * @version 1.0.0
 * @date    26.10.2025
 *
 * @brief   Детерминированные тесты для модуля bignum_mul_bignum.
 *
 * @history
 *   - rev. 1 (02.08.2025): Ошибочная первая версия тестов с некорректным сценарием.
 *   - rev. 2 (02.08.2025): Восстановлены корректные и полные тестовые
 *                         сценарии из проверенной версии 0.0.1 для
 *                         обеспечения корректного регрессионного анализа.
 *                         Код представлен полностью, без сокращений.
 */

#include "bignum_mul_bignum.h"
#include <stdio.h>
#include <string.h>
#include <assert.h>

// Вспомогательная функция для сравнения bignum_t
int bignum_are_equal(const bignum_t* a, const bignum_t* b) {
    if (a->len != b->len) {
        return 0;
    }
    return memcmp(a->words, b->words, a->len * sizeof(uint64_t)) == 0;
}

// Вспомогательная функция для копирования
void bignum_copy(bignum_t* dest, const bignum_t* src) {
    *dest = *src;
}

void test_multiply_by_zero() {
    printf("Running test: %s\n", __func__);
    bignum_t a = {.words = {123, 456}, .len = 2};
    bignum_t b = {.words = {0}, .len = 1};
    bignum_t res = {0};
    bignum_t expected = {.words = {0}, .len = 1};
    assert(bignum_mul_bignum(&res, &a, &b) == BIGNUM_MUL_BIGNUM_SUCCESS);
    assert(bignum_are_equal(&res, &expected));
    printf("...PASSED\n");
}

void test_multiply_by_one() {
    printf("Running test: %s\n", __func__);
    bignum_t a = {.words = {0xFFFFFFFFFFFFFFFF, 1}, .len = 2};
    bignum_t b = {.words = {1}, .len = 1};
    bignum_t res = {0};
    assert(bignum_mul_bignum(&res, &a, &b) == BIGNUM_MUL_BIGNUM_SUCCESS);
    assert(bignum_are_equal(&res, &a));
    printf("...PASSED\n");
}

void test_simple_multiplication() {
    printf("Running test: %s\n", __func__);
    bignum_t a = {.words = {2}, .len = 1};
    bignum_t b = {.words = {3}, .len = 1};
    bignum_t res = {0};
    bignum_t expected = {.words = {6}, .len = 1};
    assert(bignum_mul_bignum(&res, &a, &b) == BIGNUM_MUL_BIGNUM_SUCCESS);
    assert(bignum_are_equal(&res, &expected));
    printf("...PASSED\n");
}

void test_carry_multiplication() {
    printf("Running test: %s\n", __func__);
    bignum_t a = {.words = {0xFFFFFFFFFFFFFFFF}, .len = 1};
    bignum_t b = {.words = {2}, .len = 1};
    bignum_t res = {0};
    bignum_t expected = {.words = {0xFFFFFFFFFFFFFFFE, 1}, .len = 2};
    assert(bignum_mul_bignum(&res, &a, &b) == BIGNUM_MUL_BIGNUM_SUCCESS);
    assert(bignum_are_equal(&res, &expected));
    printf("...PASSED\n");
}

void test_multi_word_multiplication() {
    printf("Running test: %s\n", __func__);
    bignum_t a = {.words = {0x2, 0x1}, .len = 2};
    bignum_t b = {.words = {0x3, 0x1}, .len = 2};
    bignum_t res = {0};
    bignum_t expected = {.words = {0x6, 0x5, 0x1}, .len = 3};
    assert(bignum_mul_bignum(&res, &a, &b) == BIGNUM_MUL_BIGNUM_SUCCESS);
    assert(bignum_are_equal(&res, &expected));
    printf("...PASSED\n");
}

void test_asymmetric_multiplication() {
    printf("Running test: %s\n", __func__);
    bignum_t a = {.words = {1, 1, 1, 1}, .len = 4};
    bignum_t b = {.words = {0xFFFFFFFFFFFFFFFF}, .len = 1};
    bignum_t res;
    bignum_t a_backup;
    bignum_copy(&a_backup, &a);
    bignum_t expected = {.words = {0xFFFFFFFFFFFFFFFF, 0xFFFFFFFFFFFFFFFF, 0xFFFFFFFFFFFFFFFF, 0xFFFFFFFFFFFFFFFF}, .len = 4};
    bignum_mul_bignum_status_t status = bignum_mul_bignum(&res, &a, &b);
    assert(status == BIGNUM_MUL_BIGNUM_SUCCESS);
    assert(bignum_are_equal(&res, &expected));
    assert(bignum_are_equal(&a, &a_backup));
    printf("...PASSED\n");
}

void test_full_capacity_result() {
    printf("Running test: %s\n", __func__);
    bignum_t a = {.words = {0xFFFFFFFFFFFFFFFF, 0xFFFFFFFFFFFFFFFF, 0xFFFFFFFFFFFFFFFF}, .len = 3};
    bignum_t b = {.words = {0xFFFFFFFFFFFFFFFF, 0xFFFFFFFFFFFFFFFF, 0xFFFFFFFFFFFFFFFF}, .len = 3};
    bignum_t res = {0};
    bignum_t expected = {.words = {1, 0, 0, 0xFFFFFFFFFFFFFFFE, 0xFFFFFFFFFFFFFFFF, 0xFFFFFFFFFFFFFFFF}, .len = 6};
    assert(bignum_mul_bignum(&res, &a, &b) == BIGNUM_MUL_BIGNUM_SUCCESS);
    assert(bignum_are_equal(&res, &expected));
    printf("...PASSED\n");
}

void test_internal_zeros() {
    printf("Running test: %s\n", __func__);
    bignum_t a = {.words = {1, 0, 1}, .len = 3};
    bignum_t b = {.words = {1, 0, 1}, .len = 3};
    bignum_t res = {0};
    bignum_t expected = {.words = {1, 0, 2, 0, 1}, .len = 5};
    assert(bignum_mul_bignum(&res, &a, &b) == BIGNUM_MUL_BIGNUM_SUCCESS);
    assert(bignum_are_equal(&res, &expected));
    printf("...PASSED\n");
}

/*void test_overflow_multiplication() {
    printf("Running test: %s\n", __func__);
    bignum_t a = {.words = {1,1,1,1,1,1}, .len = 6};
    bignum_t b = {.words = {1,1}, .len = 2};
    bignum_t res = {0};
    assert(bignum_mul_bignum(&res, &a, &b) == BIGNUM_MUL_ERROR_OVERFLOW);
    printf("...PASSED\n");
}*/

void test_overflow_multiplication(void) {
    printf("Running test: %s\n", __func__);

    /* Создаём «тяжёлый» операнд a длины 32 слова (каждое слово = 1) */
    bignum_t a = { .len = BIGNUM_CAPACITY };
    for (size_t i = 0; i < a.len; i++) {
        a.words[i] = 1;
    }

    /* И ещё один, чуть короче, но так, чтобы сумма длин > 32 */
    bignum_t b = { .len = 2, .words = {1, 1} };

    bignum_t res = {0};

    /* full_len = 32 + 2 = 34 > 32, значит overflow по словесной ёмкости */
    assert(bignum_mul_bignum(&res, &a, &b)
           == BIGNUM_MUL_BIGNUM_ERROR_OVERFLOW);

    printf("...PASSED\n");
}

int main() {
    printf("\n--- Starting tests for bignum_mul_bignum ---\n");
    test_multiply_by_zero();
    test_multiply_by_one();
    test_simple_multiplication();
    test_carry_multiplication();
    test_multi_word_multiplication();
    test_asymmetric_multiplication();
    test_full_capacity_result();
    test_internal_zeros();
    test_overflow_multiplication();
    printf("--- All tests for bignum_mul_bignum passed ---\n");
    return 0;
}
