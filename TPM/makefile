compile:
	gcc -fPIC -shared tpm_test_keys.c tpm_operations.c tpm_api.c -o tpm_api.so -lwolfssl -lwolftpm

compile_test:
	gcc tpm_api.c tpm_operations.c tpm_test_keys.c tpm_api_test.c -o tpm_api_test -lwolfssl -lwolftpm

compile_test_nv:
	gcc tpm_api.c tpm_operations.c tpm_test_keys.c tpm_api_nv_test.c -o tpm_api_nv_test -lwolfssl -lwolftpm