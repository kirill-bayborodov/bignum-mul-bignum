#ifndef BIGNUM_MUL_BIGNUM_BENCHMARK_ADAPTER_H
#define BIGNUM_MUL_BIGNUM_BENCHMARK_ADAPTER_H
#include <benchmark_framework.h>
#ifdef __cplusplus
extern "C" {
#endif
typedef enum { BIGNUM_MUL_BIGNUM_BENCHMARK_STATUS_SUCCESS = 0, BIGNUM_MUL_BIGNUM_BENCHMARK_STATUS_NULL_ARGUMENT = 1, BIGNUM_MUL_BIGNUM_BENCHMARK_STATUS_INVALID_PROFILE = 2 } bignum_mul_bignum_benchmark_status_t;
bignum_mul_bignum_benchmark_status_t bignum_mul_bignum_benchmark_adapter_init(benchmark_adapter_t *adapter);
bignum_mul_bignum_benchmark_status_t bignum_mul_bignum_benchmark_validate_workload(const benchmark_workload_t *workload);
#ifdef __cplusplus
}
#endif
#endif
