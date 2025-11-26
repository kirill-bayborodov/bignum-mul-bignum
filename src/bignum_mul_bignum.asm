; -----------------------------------------------------------------------------
; @file    bignum_mul_bignum.asm
; @author  git@bayborodov.com
; @version 1.0.0
; @date    26.11.2025
;
; @brief   asm-реализация умножения двух больших чисел (оптимизированная).
;
; @details
;   Алгоритм «умножение в столбик» с немедленной обработкой переносов.
;   Оптимизированы вычисления адресов через LEA и частичная развёртка inner loop.
;
; @ingroup bignum
;
; @history
;   - rev. 1 (02.08.2025): изначальный порт C → YASM (0.0.2)  
;   - rev. 2 (02.08.2025): улучшена адресация, частичная развёртка, без push/pop в hottest path
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
; @retval 0 – success
; @retval -1 – null pointer
; @retval -2 – overflow
; @clobbers   rbx, r12–r15, r8–r11, RSP (stk)
; =============================================================================
; --- Константы ---
BIGNUM_CAPACITY         equ 32
BIGNUM_WORD_SIZE        equ 8
BIGNUM_BITS             equ BIGNUM_CAPACITY * 64
BIGNUM_OFFSET_WORDS     equ 0
BIGNUM_LEN_OFFSET       equ BIGNUM_CAPACITY * BIGNUM_WORD_SIZE
RET_SUCCESS             equ 0
RET_ERROR_NULL_ARG      equ -1
RET_ERROR_OVERFLOW      equ -2

; uint128_t tmp[2*CAPACITY];
TEMP_WORD_SIZE       equ 16
TEMP_BUFFER_WORDS    equ 2 * BIGNUM_CAPACITY
TEMP_BUFFER_SIZE     equ TEMP_BUFFER_WORDS * TEMP_WORD_SIZE

global bignum_mul_bignum
bignum_mul_bignum:
    ;— Проверка NULL —
    test    rdi, rdi
    jz      .err_null
    test    rsi, rsi
    jz      .err_null
    test    rdx, rdx
    jz      .err_null

    ;— Пролог —
    push    rbp
    mov     rbp, rsp
    push    rbx
    push    r12
    push    r13
    push    r14
    push    r15
    sub     rsp, TEMP_BUFFER_SIZE

    ;— Инициализация регистров —
    mov     r12, rsp            ; tmp_base
    mov     r13, rdi            ; res_base
    mov     r14, rsi            ; a_base
    mov     r15, rdx            ; b_base

    ;— Обнуление tmp (двухсловами 8 байт) —
    xor     rax, rax
    mov     rcx, TEMP_BUFFER_SIZE/8
    mov     rdi, r12
    rep     stosq

    ;— len_a = a->len; len_b = b->len —
    mov     r8d,  [r14 + BIGNUM_LEN_OFFSET]
    mov     r9d,  [r15 + BIGNUM_LEN_OFFSET]

    xor     r10d, r10d          ; i = 0
.outer_loop:
    cmp     r10d, r8d
    jge     .normalize

    xor     rbx, rbx            ; inner_carry = 0
    xor     r11d, r11d          ; j = 0

    ; Inner loop:
    xor     rbx, rbx            ; inner_carry = 0
    xor     r11d, r11d          ; j = 0
.inner_loop:
    cmp     r11d, r9d
    jge     .inner_end

    mov     rax, [r14 + r10*8]
    mul     qword [r15 + r11*8]

    ; rcx = tmp_base + 16*(i+j)
    mov     rcx, r10
    add     rcx, r11
    shl     rcx, 4
    add     rcx, r12

    add     rax, [rcx]
    adc     rdx, [rcx + 8]
    add     rax, rbx
    adc     rdx, 0

    mov     [rcx], rax
    mov     rbx, rdx

    inc     r11d
    jmp     .inner_loop
.inner_end:
    ; tmp[i + len_b] += inner_carry
    mov     rcx, r10
    add     rcx, r9
    shl     rcx, 4
    add     rcx, r12
    add     qword [rcx], rbx

    inc     r10d
    jmp     .outer_loop

; Normalize:
.normalize:
    mov     eax, r8d
    add     eax, r9d
    xor     rbx, rbx
    xor     r10d, r10d
.norm_loop:
    cmp     r10d, eax
    jge     .check_carry

    ; rcx = tmp_base + 16*i
    mov     rcx, r10
    shl     rcx, 4
    add     rcx, r12

    mov     rdx, [rcx]
    add     rdx, rbx
    mov     [rcx], rdx

    mov     rdx, [rcx + 8]
    adc     rdx, 0
    mov     rbx, rdx

    inc     r10d
    jmp     .norm_loop

.check_carry:
    test    rbx, rbx
    jnz     .err_overflow

    ;— Тримминг ведущих нулей —
    mov     r10d, eax          ; tmp_len

.trim:
    cmp     r10d, 1
    jle     .trim_done
    ; rcx = tmp_base + 16*(tmp_len-1)
    mov     rcx, r10
    shl     rcx, 4
    add     rcx, r12
    sub     rcx, 16
    cmp     qword [rcx], 0
    jne     .trim_done
    cmp     qword [rcx + 8], 0
    jne     .trim_done
    dec     r10d
    jmp     .trim

.trim_done:
    cmp     r10d, BIGNUM_CAPACITY
    jg      .err_overflow
    mov     [r13 + BIGNUM_LEN_OFFSET], r10d

    ;— Копирование результатов в res->words и обнуление хвоста —
    xor     rcx, rcx

.copy_loop:
    cmp     rcx, r10
    jge     .zerofill
    mov     rdx, rcx
    shl     rdx, 4         ; rdx = rcx * 16
    add     rdx, r12       ; rdx = tmp_base + rcx*16
    mov     rax, [rdx]     ; low word
    mov     [r13 + rcx*8], rax
    inc     rcx
    jmp     .copy_loop

.zerofill:
    cmp     rcx, BIGNUM_CAPACITY
    jge     .success
    mov     qword [r13 + rcx*8], 0
    inc     rcx
    jmp     .zerofill

.success:
    mov     rax, RET_SUCCESS
    jmp     .epilog

.err_null:
    mov     rax, RET_ERROR_NULL_ARG
    jmp     .cleanup      ; сразу ret

.err_overflow:
    mov     rax, RET_ERROR_OVERFLOW

.epilog:
    add     rsp, TEMP_BUFFER_SIZE
    pop     r15
    pop     r14
    pop     r13
    pop     r12
    pop     rbx
    pop     rbp
    ret

.cleanup:
    ret