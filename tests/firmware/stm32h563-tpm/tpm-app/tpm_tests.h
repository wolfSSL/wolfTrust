#ifndef WOLFTRUST_TPM_TESTS_H
#define WOLFTRUST_TPM_TESTS_H

int wt_tpm_run(void);

void wt_tpm_puts(const char *text);
void wt_tpm_print_i32(int value);
void wt_tpm_wait(void);

#endif /* WOLFTRUST_TPM_TESTS_H */
