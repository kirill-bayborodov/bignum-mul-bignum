/**
 * @file    test_bignum_mul_bignum_mt.c
 * @author  git@bayborodov.com
 * @version 1.0.0
 * @date    26.11.2025
 *
 * @brief   Тест на потокобезопасность для модуля bignum_mul_bignum.
 *
 * @details
 *   Этот тест проверяет, что функция `bignum_mul_bignum` является потокобезопасной.
 *   Он запускает несколько потоков, каждый из которых выполняет множество
 *   операций умножения. Поскольку функция является "чистой" и не использует
 *   глобальное или статическое состояние, она должна быть потокобезопасной
 *   по своей природе. Успешное завершение теста без сбоев подтверждает это.
 *
 * @history
 *   - rev. 1 (02.08.2025): Создание теста на потокобезопасность 
 */

#include "bignum_mul_bignum.h"
#include <stdio.h>
#include <pthread.h>
#include <assert.h>

#define NUM_THREADS 8
#define ITERATIONS_PER_THREAD 10000

void* thread_func(void* arg) {
    (void)arg; // Unused parameter

    for (int i = 0; i < ITERATIONS_PER_THREAD; ++i) {
        bignum_t a = {.words = {(uint64_t)i + 1, 1}, .len = 2};
        bignum_t b = {.words = {(uint64_t)i + 2, 1}, .len = 2};
        bignum_t res;

        bignum_mul_bignum_status_t status = bignum_mul_bignum(&res, &a, &b);
        assert(status == BIGNUM_MUL_BIGNUM_SUCCESS);
    }
    return NULL;
}

int main() {
    printf("\n--- Starting MT test for bignum_mul_bignum ---\n");

    pthread_t threads[NUM_THREADS];

    // Создаем потоки
    for (int i = 0; i < NUM_THREADS; ++i) {
        if (pthread_create(&threads[i], NULL, thread_func, NULL) != 0) {
            perror("pthread_create");
            return 1;
        }
    }

    // Ожидаем завершения всех потоков
    for (int i = 0; i < NUM_THREADS; ++i) {
        if (pthread_join(threads[i], NULL) != 0) {
            perror("pthread_join");
            return 1;
        }
    }

    printf("--- MT test for bignum_mul_bignum passed ---\n");
    return 0;
}
