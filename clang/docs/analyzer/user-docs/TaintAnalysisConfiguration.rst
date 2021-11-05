============================
Taint Analysis Configuration
============================

Clang Static Analyzer uses taint analysis to detect security-related issues in code.
The backbone of taint analysis in Clang is the `GenericTaintChecker`, which the user can access via the :ref:`alpha-security-taint-TaintPropagation` checker alias and this checker has a default taint-related configuration.
The checker also provides a configuration interface for extending the default settings by providing a configuration file in `YAML <https://yaml.org/>`_ format.
This documentation describes the syntax of the configuration file and gives the informal semantics of the configuration options.

.. contents::
   :local:

.. _taint-configuration-overview

Overview
________

Taint analysis works by checking for the occurrence of special events during the symbolic execution of the program.
Taint analysis defines sources, sinks, and propagation rules. It identifies errors by detecting a flow of information that originates in a taint source, touches a taint sink, and propagates through the program paths via propagation rules.
A source, sink, or an event that propagates taint is mainly domain-specific knowledge, but there are some built-in defaults provided by :ref:`alpha-security-taint-TaintPropagation`.
The checker's documentation also specifies how to provide a custom taint configuration with command-line options.

.. _taint-configuration-example:

Example configuration file
__________________________

.. code-block:: yaml

  Filters:
    # signature:
    # void cleanse_first_arg(int* arg)
    #
    # example:
    # int x; // x is tainted
    # cleanse_first_arg(&x); // x is not tainted anymore
    - Name: cleanse_first_arg
      Args: [0]

  Propagations:
  # sources:
    # signature:
    # size_t fread(void *ptr, size_t size, size_t nmemb, FILE * stream)
    #
    # example:
    # FILE* f = fopen("file.txt");
    # char buf[1024];
    # size_t read = fread(buf, sizeof(buf[0]), sizeof(buf)/sizeof(buf[0]), f);
    # // read and buf is tainted
    - Name: fread
      DstArgs: [0, -1]

  # propagations:
    # signature:
    # char *dirname(char *path)
    #
    # example:
    # char* path = read_path();
    # char* dir = dirname(path);
    # // dir is tainted if path was tainted
    - Name: dirname
      SrcArgs: [0]
      DstArgs: [-1]

  Sinks:
    # siganture:
    # int system(const char* command)
    #
    # example:
    # const char* command = read_command();
    # system(command); // emit diagnostic if command is tainted
    - Name: system
      Args: [0]

In the example file above, the entries under the `Propagation` key implement the conceptual sources and propagations, and sinks have their dedicated `Sinks` key.
The user can define program points where the tainted values should be cleansed by listing entries under the `Filters` key.
Filters model the sanitization of values done by the programmer, and providing these is key to avoiding false-positive findings.

Configuration file syntax and semantics
_______________________________________

The configuration file should have valid `YAML <https://yaml.org/>`_ syntax.

The configuration file can have the following top-level keys:
 - Filters
 - Propagations
 - Sinks

Under the `Filters` entry, the user can specify a list of events that remove taint (see :ref:`taint-filter-details` for details).

Under the `Propagations` entry, the user can specify a list of events that generate and propagate taint (see :ref:`taint-propagation-details` for details).
The user can identify taint sources with a `SrcArgs` key in the `Propagation` entry, while propagations have none.

Under the `Sinks` entry, the user can specify a list of events where the checker should emit a bug report if taint reaches there (see :ref:`taint-sink-details` for details).

.. _taint-filter-details:

Filter syntax and semantics
###########################
An entry under `Filters` is a `YAML <https://yaml.org/>`_ object with the following mandatory keys:
 - `Name` is a string that specifies the name of a function.
   Encountering this function during symbolic execution will clean taint on some parameters or the return value.
 - `Args` is a list of numbers in the range of [-1..int_max].
   It indicates the indexes of arguments in the function call event.
   The number -1 signifies the return value; other numbers identify call arguments.
   The values of these arguments are considered clean after the function call.

The following keys are optional:
 - `Scope` is a string that specifies the prefix of the function's name in its fully qualified name. This option restricts the set of matching function calls.

 .. _taint-propagation-details:

Propagation syntax and semantics
################################
An entry under `Propagation` is a `YAML <https://yaml.org/>`_ object with the following mandatory keys:
 - `Name` is a string that specifies the name of a function.
   Encountering this function during symbolic execution propagate taint from one or more parameters to other parameters and possibly the return value.
   It helps model the taint-related behavior of functions that are not analyzable otherwise.

The following keys are optional:
 - `Scope` is a string that specifies the prefix of the function's name in its fully qualified name. This option restricts the set of matching function calls.
 - `SrcArgs` is a list of numbers in the range of [0..int_max] that indicates the indexes of arguments in the function call event.
   Taint-propagation considers the values of these arguments during the evaluation of the function call.
   If any `SrcArgs` arguments are tainted, the checker will consider all `DstArgs` arguments tainted after the call.
 - `DstArgs` is a list of numbers in the range of [-1..int_max] that indicates the indexes of arguments in the function call event.
   The number -1 specifies the return value of the function.
   If any `SrcArgs` arguments are tainted, the checker will consider all `DstArgs` arguments tainted after the call.
 - `VariadicType` is a string that can be one of ``None``, ``Dst``, ``Src``.
   It is used in conjunction with `VariadicIndex` to specify arguments inside a variadic argument.
   The value of ``Src`` will treat every call site argument that is part of a variadic argument list as a source concerning propagation rules (as if specified by `SrcArg`).
   The value of ``Dst`` will treat every call site argument that is part of a variadic argument list a destination concerning propagation rules.
   The value of ``None`` will not consider the arguments that are part of a variadic argument list (this option is redundant but can be used to temporarily switch off handling of a particular variadic argument option without removing the entire variadic entry).
 - `VariadicIndex` is a number in the range of [0..int_max]. It indicates the starting index of the variadic argument in the signature of the function.


.. _taint-sink-details:

Sink syntax and semantics
#########################

An entry under `Sinks` is a `YAML <https://yaml.org/>`_ object with the following mandatory keys:
 - `Name` is a string that specifies the name of a function.
   Encountering this function during symbolic execution will emit a taint-related diagnostic if any of the arguments specified with `Args` are tainted at the call site.
 - `Args` is a list of numbers in the range of [0..int_max] that indicates the indexes of arguments in the function call event.
   The checker reports an error if any of the specified arguments are tainted.

The following keys are optional:
 - `Scope` is a string that specifies the prefix of the function's name in its fully qualified name. This option restricts the set of matching function calls.
