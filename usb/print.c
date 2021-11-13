#include "util.h"

/* 
 * The below header file contains only macros for walking
 * through a list of function arguments of an unknown type
 * and number
 */
#include <stdarg.h>

/*
 * Print format placeholder syntax is 
 *  %[parameter][flags][width][.precision][length]type
 *
 * This implementation supports only flags, width, and type
 */
enum print_states {
  STRING,
  PLACEHOLDER
};

enum placeholder_states {
  FLAGS,
  WIDTH,
  TYPE
};

/* Placeholder parameters */
#define LEFT_ALIGN     0x01
#define PAD_WITH_ZEROS 0x02

#define PH_MAX_WIDTH  20

static int put_string(struct output *out, char *s) {
  int count = 0;

  while(*s != '\0') 
    count += out->write(out->data, *s++);

  return count;
}

/* Universal print function */
static int uprintf(struct output *out, char *in, va_list args) {
  enum print_states print_s;
  enum placeholder_states placeholder_s;
  char placeholder_params;
  char placeholder_width_str[PH_MAX_WIDTH];
  char string_out[128];
  int string_len;
  char *string_tmp;
  int placeholder_width_i;
  int placeholder_width;
  char padding_char;
  int padding_len;
  int num;
  int neg_flag;
  int count;
  int i;

  count = 0;

  va_start(args, in);
  print_s = STRING;
  placeholder_s = FLAGS;
  placeholder_params = 0;
  bzero(placeholder_width_str, PH_MAX_WIDTH);
  placeholder_width_i = 0;

  /* Scan the input string */
  while(*in != '\0') {
    switch (print_s) {
      case STRING:
        switch (*in) {
          case '%': print_s = PLACEHOLDER; 
                    placeholder_s = FLAGS;
                    placeholder_params = 0;
                    bzero(placeholder_width_str, PH_MAX_WIDTH);
                    placeholder_width_i = 0;
                    break;
          default:  count += out->write(out->data, *in);
        }
        /* Proceed to the next character */
        break;
      case PLACEHOLDER:
        switch (placeholder_s) {
          case FLAGS:
            /* 
             * Flags can be zero or more, 
             * implemented flags:
             *  '-' left align this place holder
             *  '0' use zero instead of spaces to pad 
             */
            switch (*in) {
              case '-': placeholder_params |= LEFT_ALIGN;
                        break;
              case '0': placeholder_params |= PAD_WITH_ZEROS;
                        break;
              default:  placeholder_s = WIDTH;
            }
            /* 
             * If a character is a vaild flag character then
             * proceed to the next character, otherwise try
             * to interpret it as a width field 
             */
            if (placeholder_s == FLAGS)
              break;
            /* Fall-through */
          case WIDTH:
            /* Copy all digits that form the width field */
            if ((*in >= '0') && (*in <= '9')) {
              placeholder_width_str[placeholder_width_i++] = *in;
              /* Proceed to the next character */
              break;
            /* 
             * If a character is not a digit interpret the collected
             * characters as an integer and try to interpret 
             * the non-digit character as TYPE
             */
            } else {
              placeholder_width = atoi(placeholder_width_str);
              placeholder_s = TYPE;
              /* Fall-through to TYPE */
            }
          case TYPE:
            switch (*in) {
              case 'd':
              case 'i': num = va_arg(args, int);
                        neg_flag = num < 0;
                        if (neg_flag)
                          num = ~num + 1;
                        if (neg_flag)
                          string_out[0] = '-';
                        itoa(num, string_out + neg_flag);
                        break;
              case 'x':
              case 'X': itohex(va_arg(args, int), string_out);
                        break;
              case 's': string_tmp = va_arg(args, char *);
                        bcopy(string_tmp, string_out, strlen(string_tmp) + 1); /* + 1 = extra '\0'*/
                        break;
              case 'c': string_out[0] = *(va_arg(args, char *));
                        string_out[1] = 0;
                        break;
              /* 
               * If non of the above matches the provided place holder
               * is invalid and is ignored 
               */
              default: print_s = STRING;
            };
            /* Valid placeholder type, print placeholder */
            if (print_s == PLACEHOLDER) {
              string_len = strlen(string_out);

              /* Is padding necessary? */
              padding_len = placeholder_width - string_len > 0 ?
                placeholder_width - string_len : 0;

              if (padding_len) {
                padding_char = (placeholder_params & PAD_WITH_ZEROS) ? 
                  '0' : ' ';
                if (placeholder_params & LEFT_ALIGN) {
                  /* Put first string and then padding */
                  count += put_string(out, string_out);
                  for (i = 0; i < padding_len; i++)
                    count += out->write(out->data, padding_char);
                } else {
                  /* Put first padding and then string */
                  for (i = 0; i < padding_len; i++)
                    count += out->write(out->data, padding_char);
                  count += put_string(out, string_out);
                }
              } else {
                /* Padding is not necessary */
                count += put_string(out, string_out);
              }
            }
            /* Interpret the next input character as a string */
            print_s = STRING;
            break;

          default:;
            /* 
             * End of placeholder state machine 
             * we shouldn't reach the default state 
             */
        }
      default:;
        /*
         * End of print state machine 
         * We also shoud not reach the default 
         * state 
         */
    }
    /* take next character */
    *in++;
  }

  return count;
}

