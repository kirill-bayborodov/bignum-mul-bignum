/**
 * @file    bignum_mul_bignum.h
 * @author  git@bayborodov.com
 * @version 1.0.0
 * @date    26.11.2025
 *
* @brief   API для модуля умножения двух больших беззнаковых целых чисел.
 *
 * @details
 *   Эта библиотека предоставляет функцию для выполнения умножения
 *   двух чисел в формате `bignum_t`.
 *
 *   Структура bignum_t (ожидаемая):
 *   - offset 0:  uint64_t words[BIGNUM_CAPACITY] - массив слов числа.
 *   - offset 48: int32_t  len - количество используемых слов.
 *
 * @history
 *   - rev. 1 (02.08.2025): Создание версии 0.0.2. Добавлен новый код ошибки
 *                         BIGNUM_MUL_ERROR_OVERFLOW для явной сигнализации
 *                         о переполнении емкости результата.
 *
 * @see     bignum.h
 * @since   1.0.0
 *
 */

#ifndef BIGNUM_MUL_BIGNUM_H
#define BIGNUM_MUL_BIGNUM_H

#include <bignum.h>
#include <stddef.h>
#include <stdint.h>

// Проверка на наличие определения BIGNUM_CAPACITY из общего заголовка
#ifndef BIGNUM_CAPACITY
#  error "bignum.h must define BIGNUM_CAPACITY"
#endif

#ifdef __cplusplus
extern "C" {
#endif


/**
 * @brief Коды состояния для функции bignum_mul_bignum.
 */
typedef enum {
    BIGNUM_MUL_BIGNUM_SUCCESS         =  0, /**< Успешное выполнение. */
    BIGNUM_MUL_BIGNUM_ERROR_NULL_ARG  = -1, /**< Ошибка: один из входных указателей равен NULL. */
    /**
     * @brief Ошибка: переполнение емкости.
     * @details Сумма длин входных чисел (a->len + b->len) превышает
     *          емкость структуры bignum_t (BIGNUM_CAPACITY). Результат
     *          гарантированно не поместится.
     */    
    BIGNUM_MUL_BIGNUM_ERROR_OVERFLOW  = -2  /**< Ошибка: переполнение емкости. */
} bignum_mul_bignum_status_t;



/**
 * @brief Умножает два больших числа a и b, помещая результат в res.
 *
 * @details
 * **Алгоритм:**
 * 1.  Проверка входных указателей на NULL.
 * 2.  Проверка на потенциальное переполнение емкости результата.
 * 3.  Инициализация временного буфера для хранения 128-битных промежуточных
 *     произведений.
 * 4.  Выполнение умножения "в столбик" (schoolbook multiplication).
 * 5.  Нормализация результата с распространением переносов.
 * 6.  Запись финального значения и его длины в структуру `res`.
 *
 * @param res   Указатель на структуру для хранения результата.
 *              Не должен пересекаться в памяти с `a` или `b`.
 * @param a     Указатель на первый множитель.
 * @param b     Указатель на второй множитель.
 *
 * @return Код состояния `bignum_mul_bignum_status_t`.
 */
bignum_mul_bignum_status_t bignum_mul_bignum(bignum_t* res, const bignum_t* a, const bignum_t* b);

#ifdef __cplusplus
}
#endif

#endif /* BIGNUM_MUL_BIGNUM_H */
