#include <stdint.h>
#include "threads/fixed_point.h"

/* Convert integer number to 17.14 fixed point number. */
int int_to_fp (int n)
{
  return n * F;
}

/* Convert 17.14 fixed point number to integer number.(Rounding toward nearest) */
int fp_to_int_round (int f)
{
  return f >= 0 ? (f + F/2) / F : (f - F/2) / F ;
}

/* Convert 17.14 fixed point number to integer number.(Rounding toward zero) */
int fp_to_int (int f)
{
  return f / F;
}

/* Add two 17.14 fixed point numbers. */
int add_fp (int f1, int f2)
{
  return f1 + f2;
}

/* Add 17.14 fixed point number and integer number. */
int add_mixed (int f, int n)
{
  return f + int_to_fp (n);
}

/* Subtract 17.14 fixed point number from 17.14 fixed point number. */
int sub_fp (int f1, int f2)
{
  return f1 - f2;
}

/* Subtract integer number from 17.14 fixed point number. */
int sub_mixed (int f, int n)
{
  return f - int_to_fp (n);
}

/* Multiply two 17.14 fixed point numbers. */
int mult_fp (int f1, int f2)
{
  return ((int64_t) f1) * f2 / F;
}

/* Multiply 17.14 fixed point number and integer number. */
int mult_mixed (int f, int n)
{
  return f * n;
}

/* Subtract 17.14 fixed point number from 17.14 fixed point number. */
int div_fp (int f1, int f2)
{
  return ((int64_t) f1) * F / f2;
}

int div_mixed (int f, int n)
{
  return f / n;
}
