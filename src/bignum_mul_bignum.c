/**
 * @file bignum_mul_bignum.c
 * @brief C11 reference implementation for bignum_mul_bignum.
 * @details Validates inputs, computes into a stack-local temporary, normalizes
 * the result, and publishes it only after successful completion. The function
 * is deterministic, allocation-free, and safe for independent concurrent calls.
 */
#include "bignum_mul_bignum.h"
#include <string.h>

bignum_mul_bignum_status_t bignum_mul_bignum(bignum_t *res, const bignum_t *a, const bignum_t *b)
{
    bignum_t tmp = {0};
    if (res == NULL || a == NULL || b == NULL) return BIGNUM_MUL_BIGNUM_ERROR_NULL_ARG;
    if (a->len > BIGNUM_CAPACITY || b->len > BIGNUM_CAPACITY ||
        (a->len != 0U && b->len > BIGNUM_CAPACITY - a->len))
        return BIGNUM_MUL_BIGNUM_ERROR_OVERFLOW;
    for (size_t i = 0U; i < a->len; ++i) {
        __uint128_t carry = 0U;
        for (size_t j = 0U; j < b->len && i + j < BIGNUM_CAPACITY; ++j) {
            __uint128_t sum = (__uint128_t)tmp.words[i + j] +
                (__uint128_t)a->words[i] * b->words[j] + carry;
            tmp.words[i + j] = (uint64_t)sum;
            carry = sum >> 64U;
        }
        size_t k = i + b->len;
        while (carry != 0U && k < BIGNUM_CAPACITY) {
            __uint128_t sum = (__uint128_t)tmp.words[k] + carry;
            tmp.words[k++] = (uint64_t)sum;
            carry = sum >> 64U;
        }
        if (carry != 0U) return BIGNUM_MUL_BIGNUM_ERROR_OVERFLOW;
    }
    tmp.len = BIGNUM_CAPACITY;
    while (tmp.len > 0U && tmp.words[tmp.len - 1U] == 0U) --tmp.len;
    *res = tmp;
    return BIGNUM_MUL_BIGNUM_SUCCESS;
}
