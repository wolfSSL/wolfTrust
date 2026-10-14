#ifndef WOLFTRUST_PKCS11_TESTS_H
#define WOLFTRUST_PKCS11_TESTS_H

int wt_pkcs11_run(void);
const char *wt_pkcs11_suite_name(void);

void wt_pkcs11_puts(const char *text);
void wt_pkcs11_print_u32(unsigned int value);
void wt_pkcs11_wait(void);

#endif /* WOLFTRUST_PKCS11_TESTS_H */
