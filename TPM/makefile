compile:
	touch makefile
	gcc -fPIC -shared tpm_operations.c tpm_api.c -o tpm_api.so -lwolfssl -lwolftpm

compile_nv_test:
	touch makefile
	gcc tpm_api.c tpm_operations.c ./tests/tpm_api_nv_test.c -o ./tests/tpm_api_nv_test -lwolfssl -lwolftpm

compile_randgen_test:
	touch makefile
	gcc tpm_api.c tpm_operations.c ./tests/tpm_randgen_test.c -o ./tests/tpm_randgen_test -lwolfssl -lwolftpm