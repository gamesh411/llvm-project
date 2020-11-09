.. title:: clang-tidy - ericcson-cert-env32-c

ericsson-cert-env32-c
=====================

Finds functions registered by ``atexit`` and ``at_quick_exit`` that are calling
exit functions ``_Exit``, ``exit``, ``quick_exit``, ``abort`` or ``longjmp``
either in the global or in the ``std`` namespace.

Exit functions and exit handlers
--------------------------------

According to the C Standard there are three ``exit funcitons``
(``void _Exit(int status)``, ``void exit(int status)`` and
``void quick_exit(int status)``). These are no-return functions which cause the
program to terminate if called. There are also 2
``exit handler registration functions`` (``int atexit(void (*func)(void))`` and
``int at_quick_exit(void (*func)(void))``). Functions registered by ``atexit``
invocations are called before the program terminates if the termination is the
result of either returning from ``main`` or explicitly calling ``exit``.
Functions registered by ``at_quick_exit`` are called before the program
terminates if the termination is the result of explicitly calling
``quick_exit``.
The behaviour of the program is undefined if functions registered by
``exit handler registration funcitons`` do not return normally. The check
detects abnormal return by checking for calls to ``exit functions``, ``abort``
or ``longjmp`` in the body of exit handler functions.
The check also detects ``exit functions`` and other named no-return functions in
the ``std`` namespace in case a C++ code. ``Exit functions`` are also defined in
this namespace if they are imported from the ``<cstdlib>`` header.

Examples
--------

In the following example, if ``some_condition`` evaluates to true, ``exit`` is
called from an exit handler, resulting in undefined behavior.

.. code-block:: c

  #include <stdlib.h>

  void exit_handler(void) {
    /* cleanup */
    if (some_condition) {
      /* some more cleanup */
      exit(-1);
    }
    return;
  }

  int main(void) {
    if (atexit(exit_handler) != 0) {
      /* handle registration error */
    }
    /* main logic */
    return 0;
  }

The above exmaple can be fixed by not exiting expicitly in the handler.

.. code-block:: c

  #include <stdlib.h>

  void exit_handler(void) {
    /* cleanup */
    if (some_condition) {
      /* some more cleanup */
    }
    return;
  }

  int main(void) {
    if (atexit(exit_handler) != 0) {
      /* handle registration error */
    }
    /* main logic */
    return 0;
  }


In the following example ``longjmp`` is used in the exit handler, resulting in
undefined behaviour.

.. code-block:: c

  #include <stdlib.h>
  #include <setjmp.h>

  jmp_buf env;
  int val;

  void exit_handler(void) {
    /* cleanup */
    longjmp(env, 1);
  }

  int main(void) {
    if (atexit(exit1) != 0) {
      /* handle registration error */
    }
    if (setjmp(env) == 0) {
      exit(0);
    } else {
      return 0;
    }
  }

The above example can be fixed by not calling ``longjmp`` but instead returning
from the exit handler normally:

.. code-block:: c

  #include <stdlib.h>
  #include <setjmp.h>

  jmp_buf env;
  int val;

  void exit_handler(void) {
    /* cleanup */
    return
  }

  int main(void) {
    if (atexit(exit1) != 0) {
      /* handle registration error */
    }
    if (setjmp(env) == 0) {
      exit(0);
    } else {
      return 0;
    }
  }

SEI CERT Rule source: `<https://wiki.sei.cmu.edu/confluence/display/c/ENV32-C.+All+exit+handlers+must+return+normally>`_
