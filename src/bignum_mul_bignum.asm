; -----------------------------------------------------------------------------
; @file    bignum_mul_bignum.asm
; @author  git@bayborodov.com
; @version 1.0.8
; @date    01.07.2026
;
; @brief   asm-реализация умножения двух больших чисел (оптимизированная).
;
; @details
;   Алгоритм «умножение в столбик» с немедленной обработкой переносов.
;   
;
; @ingroup bignum
;
; @history
;   - rev. 1 (02.08.2025): изначальный порт C → YASM (0.0.2)  
;   - rev. 2 (02.08.2025): улучшена адресация, частичная развёртка, без push/pop в hottest path
;   - rev. 3 (26.11.2025): Оптимизация базовая. Оптимизированы вычисления адресов через LEA.
;   - rev. 4 (30.06.2026): Оптимизация с использованием Compact, Conditional-Move и Branchless
;   - rev. 5 (01.07.2026): Оптимизация:исправлен размер буфера, убраны rep-инструкции, 
;                          внутренний цикл развернут на 2 итерации (Unrolling x2), только GPR инструкции.
;   - rev. 6 (01.07.2026): Устранение деградаций и оптимизация, которая объединяет лучшие решения из предыдущих ревизий и добавляет новые
;                         - Умное зануление tmp-буфера (только len_a + len_b слов).
;                         - Loop Peeling: первая итерация (i=0) выполняется без сложения с нулями.
;                         - Unrolling x2 внутреннего цикла.
;                         - Возврат аппаратных rep-инструкций для копирования (устранение MT-деградации).
;   - rev. 7 (01.07.2026): Zeroing Elimination (удаление предварительного зануления tmp),
;                          Loop Alignment (ALIGN 16 для горячих циклов),
;                          оптимизация инструкций в trim_loop.
;   - rev. 8 (01.07.2026): Zero-copy архитектура (запись напрямую в res),
;                          удаление tmp-буфера на стеке, ранняя проверка overflow,
;                          оптимизация предсказателя ветвлений в trim_loop.
; -----------------------------------------------------------------------------

section .text

; =============================================================================
; @brief      Выполняет умножение двух больших чисел (оптимизированная).
;
; @abi        System V AMD64 ABI
; @param[in]  rdi: bignum_t* res (указатель на структуру)
; @param[in]  rsi: bignum_t* a (указатель на структуру)
; @param[in]  rdx: bignum_t* b (указатель на структуру)
;
; @return     rax: bignum_mul_bignum_status_t (0, -1 или -2)
; @clobbers   rbx, r13–r15, r8–r11, RSP (stk)
; =============================================================================
; --- Константы ---
BIGNUM_CAPACITY         equ 32
BIGNUM_WORD_SIZE        equ 8
BIGNUM_LEN_OFFSET       equ BIGNUM_CAPACITY * BIGNUM_WORD_SIZE
RET_SUCCESS             equ 0
RET_ERROR_NULL_ARG      equ -1
RET_ERROR_OVERFLOW      equ -2

global bignum_mul_bignum
bignum_mul_bignum:
    ; --- 1. Быстрые проверки на NULL ---
    test    rdi, rdi
    jz      .err_null
    test    rsi, rsi
    jz      .err_null
    test    rdx, rdx
    jz      .err_null

    ; --- 2. Пролог и выравнивание стека ---
    push    rbp
    mov     rbp, rsp
    push    rbx
    push    r13
    push    r14
    push    r15
    ; Выравнивание стека: при входе rsp % 16 == 8 (из-за call).
    ; 5 push по 8 байт = 40 байт. 40 + 8 = 48. 48 % 16 == 0. Стек выровнен.

    mov     r13, rdi            ; r13 = res_base
    mov     r14, rsi            ; r14 = a_base
    mov     r15, rdx            ; r15 = b_base

    ; Загрузка длин
    mov     r8d, [r14 + BIGNUM_LEN_OFFSET] ; len_a
    mov     r9d, [r15 + BIGNUM_LEN_OFFSET] ; len_b

    ; --- 3. Ранняя проверка на переполнение ---
    mov     r10d, r8d
    add     r10d, r9d           ; max_len = len_a + len_b
    cmp     r10d, BIGNUM_CAPACITY
    jg      .err_overflow

    ; --- 4. Полное зануление буфера res ---
    ; Зануляем все 32 слова сразу. Это branchless, крайне быстро для L1-кэша
    ; и избавляет нас от необходимости занулять хвост в конце.
    mov     ecx, BIGNUM_CAPACITY
    xor     eax, eax
    mov     rdi, r13
    rep stosq

    ; Fast-path: если хотя бы один множитель равен 0, результат 0
    test    r8d, r8d
    jz      .fast_zero
    test    r9d, r9d
    jz      .fast_zero

    ; Вычисляем четный предел для развернутого внутреннего цикла
    mov     esi, r9d
    and     esi, -2             ; esi = len_b & ~1 (округляем вниз до четного)

    ; --- 5. Loop Peeling: Первая итерация (i = 0) ---
    ; Пишем напрямую в res. Так как res занулен, мы используем mov вместо add.
    mov     rdi, [r14]          ; Кэшируем a[0]
    mov     rcx, r13            ; rcx = res_base
    xor     rbx, rbx            ; inner_carry = 0
    xor     r11d, r11d          ; j = 0

.peel_inner_loop:
    cmp     r11d, esi
    jge     .peel_odd_check

    ; Итерация 1 (j)
    mov     rax, rdi
    mul     qword [r15 + r11*8]
    add     rax, rbx            ; Сложение только с carry
    adc     rdx, 0
    mov     [rcx], rax          ; Прямая запись в res
    mov     rbx, rdx

    ; Итерация 2 (j + 1)
    mov     rax, rdi
    mul     qword [r15 + r11*8 + 8]
    add     rax, rbx            ; Сложение только с carry
    adc     rdx, 0
    mov     [rcx + 8], rax      ; Прямая запись в res
    mov     rbx, rdx

    add     rcx, 16
    add     r11d, 2
    jmp     .peel_inner_loop

.peel_odd_check:
    cmp     r11d, r9d
    jge     .peel_inner_end

    ; Итерация для последнего нечетного элемента
    mov     rax, rdi
    mul     qword [r15 + r11*8]
    add     rax, rbx
    adc     rdx, 0
    mov     [rcx], rax
    mov     rbx, rdx
    add     rcx, 8

.peel_inner_end:
    mov     [rcx], rbx          ; Записываем финальный carry для i=0
    mov     r10d, 1             ; i = 1

    ; --- 6. Основной цикл умножения (i > 0) ---
.outer_loop:
    cmp     r10d, r8d
    jge     .trim_start

    mov     rdi, [r14 + r10*8]  ; Кэшируем a[i]
    lea     rcx, [r13 + r10*8]  ; rcx = res_base + i*8
    xor     rbx, rbx            ; inner_carry = 0
    xor     r11d, r11d          ; j = 0

    ; Внутренний цикл (Unrolled x2)
.inner_loop_unrolled:
    cmp     r11d, esi
    jge     .inner_odd_check

    ; Итерация 1 (j)
    mov     rax, rdi
    mul     qword [r15 + r11*8]
    add     rax, [rcx]          ; Складываем с текущим значением в res
    adc     rdx, 0
    add     rax, rbx            ; Складываем с carry
    adc     rdx, 0
    mov     [rcx], rax
    mov     rbx, rdx

    ; Итерация 2 (j + 1)
    mov     rax, rdi
    mul     qword [r15 + r11*8 + 8]
    add     rax, [rcx + 8]      ; Складываем с текущим значением в res
    adc     rdx, 0
    add     rax, rbx            ; Складываем с carry
    adc     rdx, 0
    mov     [rcx + 8], rax
    mov     rbx, rdx

    add     rcx, 16
    add     r11d, 2
    jmp     .inner_loop_unrolled

.inner_odd_check:
    cmp     r11d, r9d
    jge     .inner_end

    ; Итерация для последнего нечетного элемента
    mov     rax, rdi
    mul     qword [r15 + r11*8]
    add     rax, [rcx]
    adc     rdx, 0
    add     rax, rbx
    adc     rdx, 0
    mov     [rcx], rax
    mov     rbx, rdx
    add     rcx, 8

.inner_end:
    mov     [rcx], rbx          ; Записываем финальный carry
    inc     r10d
    jmp     .outer_loop

    ; --- 7. Тримминг ведущих нулей (Оптимизированный) ---
.trim_start:
    mov     r10d, r8d
    add     r10d, r9d           ; max_len = len_a + len_b
    jz      .fast_zero          ; Если 0 (на всякий случай)

    ; Проверяем самое старшее слово без цикла (самый частый кейс)
    ; Это позволяет избежать branch-misses в 99% случаев
    cmp     qword [r13 + r10*8 - 8], 0
    jnz     .trim_done
    dec     r10d
    jz      .trim_done          ; Если осталась длина 0

.trim_loop:                     ; Сюда попадем крайне редко
    cmp     qword [r13 + r10*8 - 8], 0
    jnz     .trim_done
    dec     r10d
    jnz     .trim_loop
    jmp     .trim_done

.fast_zero:
    xor     r10d, r10d          ; Если умножали на 0, итоговая длина = 0

    ; --- 8. Завершение ---
.trim_done:
    mov     [r13 + BIGNUM_LEN_OFFSET], r10d
    mov     eax, RET_SUCCESS
    jmp     .epilog

    ; --- 9. Обработка ошибок ---
.err_overflow:
    mov     eax, RET_ERROR_OVERFLOW
    jmp     .epilog

.err_null:
    mov     eax, RET_ERROR_NULL_ARG
    ret                         ; Ранний возврат, стек еще не трогали

    ; --- 10. Эпилог ---
.epilog:
    pop     r15
    pop     r14
    pop     r13
    pop     rbx
    pop     rbp
    ret
