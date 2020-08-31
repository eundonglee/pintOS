#ifndef THREADS_FIXED_POINT_H
#define THREADS_FIXED_POINT_H

#include <stdint.h>

/* Define the functions to denote and calculate numbers in 17.14 fixed point format */

#define F (1 << 14)
#define INT_MAX ((1 << 31) - 1)
#define INT_MIN (-(1 << 31) -1)

int int_to_fp (int n);
int fp_to_int_round (int f);
int fp_to_int (int f);
int add_fp (int f1, int f2);
int add_mixed (int f, int n);
int sub_fp (int f1, int f2);
int sub_mixed (int f, int n);
int mult_fp (int f1, int f2);
int mult_mixed (int f, int n);
int div_fp (int f1, int f2);
int div_mixed (int f, int n);

#endif 
