# Purpose
ASN1ToROS-Generator: The purpose of this library is to generate messages from the ASN1-format for ROS2.

## Hints:

If this error message appears: "config.status: error: cannot find input file: 'tests/tests-c-compiler/check-src/Makefile.in'"
run the following command:

```bash
autoheader \
    && aclocal \
    && libtoolize --ltdl --copy --force \
    && automake --add-missing --copy \
    && autoconf \
    && ./configure
```
