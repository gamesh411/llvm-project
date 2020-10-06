===============================
Container and Iterator Modeling
===============================

The goal of checker ``alpha.cplusplus.ContainerModeling`` is to provide a
symbolic abstraction for containers to the Clang Static Analyzer. There are
various concepts regarding containers that help formulate static analysis
problems more concisely. The size of the container, whether is empty or not are
the most trivial motivating examples. Standard containers can be iterated, and
this idiom is well-adopted in case of non-standard container implementations as
well, because it can be used to provide a compatible interface to algorithms.
Therefore iterator modeling is closely related to containers. Iterators extend
the range of useful properties when it comes to finding bugs, for example, which
container an iterator belongs to, what position inside the container it is in,
and whether it is a valid or invalid state (see rules for `iterator invalidation
<https://en.cppreference.com/w/cpp/container#Iterator_invalidation>`_).
Iterator modeling is implemented in checker ``alpha.cplusplus.IteratorModeling``.

There are also various checkers which make use if the information provided by
the modeling checkers mentioned:
  * :ref:`alpha-cplusplus-InvalidatedIterator`
  * :ref:`alpha-cplusplus-IteratorRange`
  * :ref:`alpha-cplusplus-MismatchedIterator`


Definition of a container
-------------------------

According to ContainerModeling, a value ``c`` with type ``C`` is considered a
container if either of the following holds:
  * The expression ``c.begin()`` and ``c.end()`` are both valid expressions, and
    return an `iterator
    <https://en.cppreference.com/w/cpp/iterator#Iterator_categories>`_.
    This should be detected by type C having member functions ``T C::begin()``
    and ``T C::end()``, where T is an `iterator
    <https://en.cppreference.com/w/cpp/iterator#Iterator_categories>`_.
  * The expression ``begin(c)`` and ``end(c)`` are both valid expressions in a
    given scope, and return an `iterator
    <https://en.cppreference.com/w/cpp/iterator#Iterator_categories>`_.
    This should be detected by checking the existence functions with the
    corresponding names, and can either be user-defined free functions or
    template specialization of the standard-defined ``template<typename T>
    constexpr auto std::begin(T& t) -> decltype(t.begin())`` and
    ``template<typename T> constexpr auto std::end(T& t) ->
    decltype(t.end())`` function templates (see `std::begin
    <https://en.cppreference.com/w/cpp/iterator/begin>`_ and `std::end
    <https://en.cppreference.com/w/cpp/iterator/end>`_).

Example containers in STL (with different `invalidation properties
<https://en.cppreference.com/w/cpp/container#Iterator_invalidation>`_)
 - std::array
 - std::vector
 - std::deque
 - std::list
 - std::forward_list

Example of a custom container with member functions.

.. code-block:: cpp

  class C {
    std::vector<int> v;
  public:
    using iterator = typename std::vector<int>::iterator;

    iterator begin() { return v.begin(); }
    iterator end() { return v.end(); }
  };


Example of a custom container with free functions.

.. code-block:: cpp

  class C {
    std::vector<int> v;
  public:
    using iterator = typename std::vector<int>::iterator;
  
    friend iterator begin(C&);
    friend iterator end(C&);
  };

  C::iterator begin(C& c) { return c.v.begin(); }
  C::iterator end(C& c) { return c.v.end(); }

Example of a custom container with std template specialization.

.. code-block:: cpp

  class C {
    std::vector<int> v;
    auto begin() { return v.begin(); }
    auto end() { return v.end(); }
  public:
    template<typename T>
    friend constexpr auto std::begin(T& t) -> decltype(t.begin());
    template<typename T>
    friend constexpr auto std::end(T& t) -> decltype(t.end());    
  };

Modeling of a container
-------------------------

A container is modeled if it has an associated ``MemRegion``, and this ``MemRegion``,
or rather the ``const MemRegion*`` (and pointers to its subclasses), that is accessible
by the ``MemRegionManager`` is what uniquely identifies a container. Temporary
containers do not necessarily have a ``MemRegion``, these are not modeled.

A container is tracked from the ``ProgramPoint``, where either ``begin`` or ``end``
member function (or free function) is called. Abstract modeling uses ``SymbolRef``-s for the
begin and end positions of a container. Any relations between the two positions are tracked
in form of assumptions (inside ``ConstraintManager``).
For specifying positions inside the container we use one of the following expressions
  - ``<begin-symbol> + <concrete-value>`` for specifying a position relative to the beginning of the container.
  - ``<end-symbol> - <concrete-value>`` for specifying a position relative to the end of the container.
  - ``<conjured-symbol>`` for unknown positions inside the container.

.. note ::
  ``using clang::ento::SymbolRef = typedef const SymExpr *``

Containers are modeled in the GDM by their region (MemRegion*) as their associated key,
this region is immutable, it cannot change during the lifetime of the modeled object.
The begin and end symbols are conjured and are completely unrelated to the region of
the container. For each region we store the only the begin and end symbols, other properties
are to be computed from these, and their relationships stored in the ContstraintManager.

The symbolic-value categories (``SVal`` subclasses) encountered during container modeling
are ``Loc`` (and subclasses, most prominently ``ConcreteInt`` and ``MemRegionVal``), as
temporary containers are not modeled.

Apart from identifying the container with a ``MemRegion``, in order to interact with
iterator modeling, the symbolic begin and end positions of the container are also tracked.
The size (and as a special case, whether the container is empty or not) are properties that
should also be tracked.

.. note::
  Currently, the implementation does not handle size and emptiness tracking, but patches
  can be found for them on Phabricator: `size <https://reviews.llvm.org/D76604>`_ and
  `empty <https://reviews.llvm.org/D76590>`_.

Implementation limitations
--------------------------

There are some limitations which must be circumvented in order to effectively implement
container modeling. The problem of RValue/LValue (more precisely prvalue, xvalue, and
lvalue see `value categories <https://en.cppreference.com/w/cpp/language/value_category>`_)
modeling is not prominent is case containers alone, as no temporary objects are considered.
However, this is an issue to be solved when it comes to modeling iterators.

.. note::
  Containers as RValues are currently not relevant, but size modeling could use them, as the
  modeling of copy constructors are needed.
  No constructors of containers are modeled, there is a WIP
  `patch <https://reviews.llvm.org/D87388>`_ for default constructor.

There is a limitation in the size of Symbols handled by ``the ConstraintManager``, namely that
every offset is assumed to be at most ``typesize/4`` in size, otherwise the ``ConstraintManager``
could not reorder expressions containing the the symbol. As an orthogonal issue symbol-symbol
comparisons still cannot be handled properly if the ``ContstraintManager`` would also be able
answer questions like: is symbol A less than symbol B (instead of just reporting the possible
range of the values a symbol can have).

.. note::
  There is a WIP extension: if range of 2 symbols is disjunct and the max of first is less than
  the min of the second, report less relation. `patch <https://reviews.llvm.org/D77792>`_
  This patch would be needed to compare the sizes of containers.
  If the containers don't overlap in memory, then this would provide a way to determine the size
  differences. E.g.: If we could store ``a = b + 5`` even if the ranges of a and b is unknown,
  reordering of this would produce: ``a - b = 5`` and this can have a range attached in the
  abstract state.

=================
Iterator Modeling
=================

Definition of an iterator
-------------------------

A value with type T is possibly considered an iterator:
If T is
  - copy-constructible
  - copy-assignable
  - destructible
  - can be incremented (both post and prefix unary plus-plus operator are defined)
AND
T meets the requirements of either input or output iterator
  - in case of input:

    - dereference operator with an rvalue return type is defined (both ``operator*`` and ``operator->``)
    - equality/inequality comparable (both bool ``operator==`` and bool ``operator!=`` are defined)
  - in case of output:

    - dereference operator with an lvalue return type is defined (both ``operator*`` and ``operator->``)
    - (note in this case no equality/inequality is required)

The iterator modeling takes these into consideration only during the detection of iterators, and the
iterator-category is not stored explicitly.

Modeling of an iterator
-----------------------

The tracking of an iterator begins if a value is detected with the preceding properties *and* its name
has 'iterator'/'iter'/'it' postfix. In special cases pointers are also treated as iterators, namely,
if they are results of ``begin`` or ``end`` member functions or free functions.

The following heuristics are also in place to limit the tracking of many unrelated iterators:
 - only track an iterator if its generating expression has a tracked container (and this will be the parent container of the returned iterator)
 - only track an iterator if its generating expression is a function call which has at least 1 argument, that is an already tracked iterator (and the first iterator parameter's container will be the parent container of the returned iterator)
If either of these heuristics matches the tracking of iterator should be skipped.

Iterators are modeled in the GDM with 2 kinds of keys:
  - Region (``const MemRegion*``)
  - Symbol (``SymbolRef``)
There are therefore 2 maps which model iterators, one is called the RegionMap, the other is the SymbolMap.

For each iterator the following information is stored:
  - a flag signifying the validity of the iterator
  - a reference to the container it belongs to (parent container)
  - the offset of this iterator inside the (parent container)

The iterator offset is abstract, no ``MemRegionVal`` is associated with iterator offsets.

  - a single conjured symbol (SymbolVal)
  - a conjured symbol (SymbolVal) + a number (``ConcreteInt``) (This for is useful for reordering)

Functions like find (when alpha.cplusplus.STLAlgorithmModeling is enabled) handle cases where an
element is found, and a case where it is not
  - found case: ``return it >= 1.parameter`` AND ``it < 2.parameter`` constraints are applied
  - not-found case: ``it == 2.parameter`` constraint is applied
Assert should be used if the element is KNOWN to be in the container (invariant property of the usage)

There are currently 2 main categories of iterators, one is implemented with pointers, the other is via class
instances. The goal is to handle iterators in a uniform fashion for the 2 iterator implementations.

Example of a pointer iterator implementation (conceptionally no difference between inline and non-inline modes)

.. code-block:: cpp

  struct Cont {
    using iterator = int*;
    int v[8];
    iterator end_pos;
  
    iterator begin() {
      return v;
    }
  
    iterator end() {
      return end_pos;
    }
  
    // methods handling container operations
  }

A detailed example of modeling a container and its iterators.

.. code-block:: cpp

  void f() { 
    Cont c;              // no modeling should be done here

    int* it = c.begin(); // container-modeling begins by tracking c as a container of type Cont
                         // begin() member function call triggers the modeling
                         // iterator-modeling also begins by tracking the value of c.begin()
                         // as an iterator
                         // we check if the value has the necessary iterator-properties
                         // ExprEngine handles the binding of RValue c.begin() to the value of it.

    ++it;                // it is a tracked iterator, operator++ is a relevant operation
                         // ExprEngine creates new ElementRegion for the incremented iterator,
                         // and binds this (RValue) SVal to variable it (LValue)
  
    if (!(it == c.end())) { // c.end() triggers container-modeling again, producing an iterator
                            // position, noting it in the modeling structure for c as end position
                            // comparion operator== triggers a state-split, branch a assuming that
                            // it position is equal to the newly created end position, branch b
                            // has the opposite assumption
      use(*it);             // Iterator modeling does not do anything with this dereference
                            // operator-call, but checkers can use the information aggregated by
                            // modeling to ensure that the iterator is valid in this case (because
                            // of the if guarding it)
    }
  }


Implementation limitations
--------------------------

Contrary to the container-modeling, not only lvalue iterators are tracked. This is the reason
why 2 different keys are used in the GDM for iterators. An lvalue iterator has a Region
(``const MemRegion*``) and it is used if available. If no Region is found for an iterator value
then a Symbol is used (``SymbolRef``).

In the case of pointer iterators (where std::is_pointer<T>::value is true for the type T of the iterator),
the modeling of the symbolic value is simpler. The lifetime of such values is simple to model,
there is no need for constructors, destructors and copy-elision rules to be taken into consideration.

Example of a pointer iterator.

.. code-block:: cpp

  int * it = cont.begin();
  int * it = it + 1 + 1;
  // SVal of it + 1 subexpression: NonLoc kind (designates an RValue)


The operators of such iterators are built-in operators.

Iterators implemented as pointer live generally in the SymbolMap (the map containing ``SymbolRef``-s as
opposed to the map containing the ``const MemRegion*``-s), and can not be only represented with LValues (and
consequently inside the RegionMap), as tracking the value of symbolic offset of an iterator must handle
expressions where there may only be temporaries with no LValues associated with them.

We cannot consistently track only LValues (``MemRegionVal``-s) or only ``RValues`` (``SymbolVal`` or ``LazyCompoundVal``),
because pointer iterators have only Rvalues that always identifies them (across multiple subexpressions),
class instance variables only have Lvalues for this role. SymbolMap always has iterator values that are RValues.
RegionMap can have iterator values which are LVals but also values which are RValues.

In case of class instance implemented iterators, the operations are ``CXXOperatorCallExpr``-s (not built-in
operators). Also sometimes RValues of such instances are modeled as ``LazyCompoundVal`` ``SVal``-s, but can
also appear as ``MemRegionVal`` or ``SymbolVal`` (if ``std-container-inlining`` analyzer option is off).

The modeling of special container-related member functions can be found in ``Iterator.cpp``, and
algorithm modeling in ``STLAlgorithmModeling.cpp``.

The semantic difference between the 2 iterator implementation with respect to their ``SVals`` is
that accessing a pointers ``SVal`` always return reference to a Region (no way to be a symbol, SymRegion),
but in case if a class instance iterator can be a symbol (SymExpr).

Example of a class instance iterator.

.. code-block:: cpp

  class cont_it {...};
  cont_it it = cont.begin();
  cont_it it = it + 1 + 1;
  // SVal of it + 1 subexpression: Loc kind (designates an RValue)

Example of a container which has iterators as elements.

.. code-block:: cpp

  using it_t = int*;

  std::vector<it_t> v;
  vector_it it = v.begin(); // container modeling detects v as container
  it = it + 1;

.. note::
  This is the main issue right now, using these two maps in a more organized fashion, or providing a
  straightforward way to manage the symbolic values of iterators is essential to effectively progress with the 
  implementation. Also the case of nested iterator modeling (where there is a container which has iterator
  as elements) the iterators that iterate a container and the iterators contained in the said container must be
  distinguished).
  The question is what to track in the GDM, and how to identify the correct iterator value.
  
  3 options have been outlined so far.

  **Option 1**: use only RValues (``SymbolRef``-s) as keys
  Class instance iterators (possibly with ``LazyCompoundVal``) can not be used as keys as they are now, because
  they do not satisfy map key criteria (this could be maybe solved by defining an ordering on them), but the
  main issue is that even though they wrap a SymbolVal, this wrapping is an implementation detail and should not
  be relied upon, also meaning they should not be unwrapped.
  Pointer iterators do not have an issue with this option.

  **Option 2**: use only LValues (``const MemRegion*``) as keys
  Class instance iterators that evaluate as a result of multiple subexpressions have RValues and these immediate
  RValues break a cheain of value propagation. lazyCompoundVal should not be used as keys in a map (every
  operation results in a temporary which can be tracked).
  Pointer iterators that evaluate as a result of multiple subexpressions have RValues and these immediate RValues break
  the chain of value propagation. lazyCompoundVal should not be used as keys in a map (every operation results in a
  temporary which can be tracked). no temporaries are created during the evaluation of expressions (i + 1 + 2) there
  is no intermediate lvalue for i + 1.

  **Option  3**: In case of pointer iterators a solution could be to only track the RValues, and in the case of class
  instance iterators use both RValues and LValues, and this way we track the explicit nature of being pointer based
  or being class instance based.
  The drawback of this approach is that the implementation for modeling the 2 families of iterators are harder to
  share, which either leads to duplication or an extra layer of abstraction.
  The ability of LazyCompoundVal to take the role of the key inside the map (ordering or hashing) should still be
  solved in this case (as in Option 1).




