/* FreeRTOSConfig.h for the wolfTrust FreeRTOS NS guest.
 *
 * Tuned for the ARM_CM33_NTZ/non_secure port: TrustZone awareness OFF
 * (the secure side owns CMSE; this guest treats the world as flat NS),
 * MPU OFF (the secure side already programs an MPU window per guest),
 * FPU OFF (the wolfTrust build is -mgeneral-regs-only). Heap is small
 * — guest1 RAM is 32 KiB total and the wolfHSM transport CSR carves
 * the bottom of it. */

#ifndef FREERTOS_CONFIG_H
#define FREERTOS_CONFIG_H

#include <stdint.h>

/* Cortex-M33 NTZ port — TrustZone-unaware. */
#define configENABLE_MPU                          0
#define configENABLE_FPU                          0
#define configENABLE_TRUSTZONE                    0

/* Scheduler. */
#define configUSE_PREEMPTION                      1
#define configUSE_TIME_SLICING                    1
#define configUSE_PORT_OPTIMISED_TASK_SELECTION   0
#define configMAX_PRIORITIES                      4
#define configIDLE_SHOULD_YIELD                   1
#define configUSE_16_BIT_TICKS                    0

/* Tick / clock. */
#define configCPU_CLOCK_HZ                        240000000u
#define configTICK_RATE_HZ                        100u
#define configSYSTICK_CLOCK_HZ                    configCPU_CLOCK_HZ

/* Heap (heap_4.c). The wolfPSA + wolfCrypt cryptocb path allocates
 * key scratch buffers on the FreeRTOS heap, so it needs a few KiB. */
#define configTOTAL_HEAP_SIZE                     ( (size_t) ( 16 * 1024 ) )
#define configSUPPORT_DYNAMIC_ALLOCATION          1
#define configSUPPORT_STATIC_ALLOCATION           0
#define configMINIMAL_STACK_SIZE                  ( (uint16_t) 256 )
#define configMAX_TASK_NAME_LEN                   12

/* Features in / out. */
#define configUSE_MUTEXES                         1
#define configUSE_TICKLESS_IDLE                   0
#define configUSE_APPLICATION_TASK_TAG            0
#define configUSE_NEWLIB_REENTRANT                0
#define configUSE_CO_ROUTINES                     0
#define configUSE_COUNTING_SEMAPHORES             0
#define configUSE_RECURSIVE_MUTEXES               0
#define configUSE_QUEUE_SETS                      0
#define configUSE_TASK_NOTIFICATIONS              1
#define configUSE_TRACE_FACILITY                  0
#define configUSE_IDLE_HOOK                       0
#define configUSE_TICK_HOOK                       0
#define configCHECK_FOR_STACK_OVERFLOW            0
#define configUSE_MALLOC_FAILED_HOOK              0

/* Software timers — off for the smoke. */
#define configUSE_TIMERS                          0

/* INCLUDE_* — only what we use. */
#define INCLUDE_vTaskPrioritySet                  0
#define INCLUDE_uxTaskPriorityGet                 0
#define INCLUDE_vTaskDelete                       1
#define INCLUDE_vTaskSuspend                      1
#define INCLUDE_vTaskDelayUntil                   0
#define INCLUDE_vTaskDelay                        1
#define INCLUDE_xTaskGetSchedulerState            0
#define INCLUDE_xTaskGetCurrentTaskHandle         0

/* Cortex-M33 NVIC priority configuration. ARM standard: 8 bits, 4
 * priority bits implemented on STM32H5. PRIO_BITS / LIBRARY_LOWEST_PRIO
 * follow ARM CMSIS conventions; LIBRARY_MAX_SYSCALL_PRIO controls which
 * NVIC priorities can call FreeRTOS API from ISRs. */
#define configPRIO_BITS                           4
#define configLIBRARY_LOWEST_INTERRUPT_PRIORITY   ((1 << configPRIO_BITS) - 1)
#define configLIBRARY_MAX_SYSCALL_INTERRUPT_PRIORITY  2
#define configKERNEL_INTERRUPT_PRIORITY \
    (configLIBRARY_LOWEST_INTERRUPT_PRIORITY << (8 - configPRIO_BITS))
#define configMAX_SYSCALL_INTERRUPT_PRIORITY \
    (configLIBRARY_MAX_SYSCALL_INTERRUPT_PRIORITY << (8 - configPRIO_BITS))

/* CM33 NTZ port maps SVC / PendSV / SysTick directly to the FreeRTOS
 * handlers; this guest's vector table at apps/freertos_guest1/main.c
 * threads them through. */
#define vPortSVCHandler                           SVC_Handler
#define xPortPendSVHandler                        PendSV_Handler
#define xPortSysTickHandler                       SysTick_Handler

/* Run-time / asserts. */
#define configASSERT( x ) do { if (!(x)) { for(;;) {} } } while (0)

#endif /* FREERTOS_CONFIG_H */
