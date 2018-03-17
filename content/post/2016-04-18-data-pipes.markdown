---
title: "C++ Data Pipes"
date: 2016-04-18T18:00:00
disqusid: 1947
series: Language
categories: Language
---

Many modern languages have the ability to chain function calls together using the **_natural order_** in a typesafe way. We can now accomplish this in _C++14_. Consider the following code.

<center class="caption"><a name="basic_pipe_code">basic pipe code</a></center>
```cpp
auto muffins =
4
| [](int x){ return vector<string>(x, "muffin"); }
| reduce( [](string x, string y) { return x + "\n" + y; } );

cout << muffins << endl;
```

```bash
$ ./run
muffin
muffin
muffin
muffin
```
What's happening here is quite straightforward. The integer 4 is piped into a function that turns it into a vector of 4 muffins. That vector of 4 muffins is then piped into a function that reduces it into a printable string. The order of the code here is considered to be natural in that we start with a piece of data a pipe it through a series of functions to get a result. To contrast this with something a bit less natural consider the following equivalent _C++_ code.

```c++
string s = 
reduce( [](string x, string y) { return x + "\n" + y; } )(
  vector<string>(4, "muffin") 
);

cout << s << endl;
```

This code **first** computes a reducer function, **then** creates the muffin vector and **finally** creates the printable string representation. This is less natural in the sense that we are formulating the function to act on a specific piece of data before the data itself is introduced. This example of course is quite trivial, but the effects become more pronounced on more complicated function compositions as we will see later. When writing code in this style, I often find myself writing the sequence of function calls inside-out, starting from the data and progressively wrapping functions around it. The result is a very gross Lispy looking thing.

Returning now to the <a href="#basic_pipe_code">basic pipe code</a>. Notice that the function pipeline is glued together by pipe operators. What is the type of the pipe operator? This one is actually a delightfully simple function template.

<center class="caption"><a name="pipe_operator">the pipe operator</a></center>
```c++
template< typename C, typename F>
auto
operator | (C && c, F f)
{
  return f(c);
}
```
The _lhs_ of the operator is given the type parameter ```C``` and is passed in by a **universal reference** e.g., it will take on the type qualifiers of whatever is passed in (pass by reference, value, const reference, etc.). ```F``` must be a function that accepts a single parameter of type ```C``` as can be seen from the body of the template where ```f(c)```. The return type of this function template is deduced by the compiler and is dependent and bound to the return type of ```f```, whatever that may be. Thus the pipe operator simply calls the function that is its _rhs_ on the data that is its _lhs_.

So far so good? Now let's take a look at the ```reduce``` function, which is where the _C++14_ goodness really starts to kick in. ```reduce``` is a **higher order function**. It takes a function as its input parameter and its return value is also a function. The input function reduces a pair of values into a single value and the return function applies that pairwise reduction function iteratively over a sequence of values.

The reduce function is implemented as the composition of two templates. We will look at them one at a time. The first template below builds the pairwise reduction function that operates over a sequence of values.

<center class="caption"><a name="reduce_0">reduce level 0</a></center>
```c++
template < typename F >
auto
reduce(F f)
{
  return [f](auto && c){ return do_reduce(c, f); };
}
```
The power of this template is captured in the two ```auto``` types that the compiler deduces for us. The first ```auto``` is the return type deduction that we saw before. Return type deduction has been available since _C++11_ however it is now much easier to use in that we don't have to tell the compiler what auto resolves to ourselves by using decltypes in terms of the function call arguments.

The really nifty ```auto``` is the one that appears in the lambda expression in the body of the template. This is more or less a templated lambda expression without the syntactic grossness of angle brackets. The type of ```c``` that ```auto``` resolves to is done ***at the time of the call site*** by the compiler. Because ```reduce``` itself is a template, that is the only way this could happen anyhow, the compiler only instantiates the template and generates code when it is called from somewhere else in the code. However, this has the lovely side effect in this case of delaying the type inference of ```c``` until the compiler knows what the type of ```f``` is. Furthermore the function do_reduce is a template and further constrains the type of ```c``` as we will see next.

<center class="caption"><a name="reduce_1">reduce level 1</a></center>
```c++
template < 
  typename A,
  template <typename, typename...> class C, 
  typename F, typename ...AT
>
auto
do_reduce(C<A,AT...> & c, F f)
{
  return std::accumulate(c.begin()+1, c.end(), *c.begin(), f);
}
```

This template is a bit more complicated, but also shows some powerful new _C++_ features. This template takes a collection template of type ```C<A,AT...>``` the ellipsis argument essentially means 'more arguments of varying types'. There is template machinery  to iterate through those arguments, but I am not going to get into that here. In this case we simply forward the arguments on. The use of this so called [variadic template](http://en.cppreference.com/w/cpp/language/parameter_pack) structure is simply because we want to support several standard library collections such as ```vector```, ```set```, ```list``` etc., with this single template. These functions all take further template arguments such as allocators and freers, but we are not concerned with them here, or their types for that matter so we simply pass them along.

Like we said before, the reduce function does a pairwise reduction over a sequence of elements. That reduction is actually done by the standard library function ```accumulate```. No sense in reimplementing the wheel here, we are just making the wheel easier on the eyes. This template definition puts substantial constraints on the types of ```c``` and ```f```, which the compiler will use in deducing the ```auto && c``` variable from <a href="#reduce_0">reduce level 0</a>. In detail, we require that the function ```f``` can operate over the elements of ```c``` by using an [input iterator](http://en.cppreference.com/w/cpp/concept/InputIterator) interface on ```c```. This is in addition to the fact that ```c``` must be a template itself that takes at least 1 argument (the ellipsis can be empty).

All of this is figured out at the latest possible moment by the compiler, which also happens to be the first moment at which it has enough information to determine all the types in play. That is the moment at which the function that is returned from ```reduce``` is itself called. In the  [basic pipe code](#basic_pipe_code), the function is called by the pipe operator (another template) which delivers as the argument the output of the previous lambda whose return type is also deduced at compile time. Note that none of this would work without the auto lambda. Well that's not actually grue, given the proper template meta-programming black magic this could be made to work without the auto lambda, but it would likely be completely inscrutable code. But what we have here is relatively straightforward type deduction that done by the compiler and _not_ our template code that is approaching Haskell-esk power, which is quite nifty.

The astute reader may notice that we don't actually need two templates to do this. We could just write the following directly.

```c++
template < typename F >
auto
reduce(F f)
{
  return [f](auto && c)
  { 
    return std::accumulate(c.begin()+1, c.end(), *c.begin(), f);
  };
}
```

And indeed this works just fine. I just factored out a second template to introduce the concept of using variadic templates to simplify passing complex templates around polymorphically. Now consider the following code for a ```map``` function in which the factorization becomes necessary. First the caller facing API level templates. For map there are two. 

The first one is for a map that transforms the contents of the collection with the given function ```f``` and returns back the same type of collection it got in. The second one allows the user to specify an additional template argument that will transform the collection as well into a new type of collection.

```c++
template < typename F >
auto
map(F f)
{
  return [f](auto & c){ return do_map(c, f); };
}
```

```c++
template < template <typename, typename...> class C, typename F >
auto
map(F f)
{
  return [f](auto & c){ return do_map<C>(c, f); };
}
```

Now for the implementation of these templates. Beginning with the implementation that returns the same type of collection as it receives by default.

```c++
template < 
  typename A,
  typename F,
  template <typename, typename...> class C, 
  template <typename, typename...> class CC = C,
  typename ...AT
>
auto
do_map (C<A,AT...> & c, F f) 
{
  using T = typename std::result_of<F(A&)>::type;
  CC<T> result;
  result.reserve(c.size());
  std::transform(c.begin(), c.end(), std::inserter(result, result.end()), f);
  return result;
}
```

In the first line of the body of this template we construct the value type of the collection it is going to return. The ```typename``` keyword indicates to the compiler that we are specifying a type and the [result_of](http://en.cppreference.com/w/cpp/types/result_of) template is a standard library template that does the metaprogramming work of determining the result of a function type applied to an argument type. Using the computed type ```T``` we construct an instance of the result container as ```C<T>```. The template ```CC``` is extracted by the compiler when the template ```do_map``` is called. Notice that in this function ```CC``` is defaulted to the value of ```C```. However this default can be explicitly overriden depending on how the template is called as we will see in the next piece of code. Once the result container is constructed, the space to fill it with transformed variables is reserved. This is not necessary but improves performance for large collections, because we know the size of the input data exactly, we can allocate the required output collection space up front all at once instead of letting the C++ runtime expand the memory allocation on an as-needed basis. Again not reinventing the wheel we use the standard library [transform](http://en.cppreference.com/w/cpp/algorithm/transform) function to actually perform the mapping computation.

Here the two template factorization becomes necessary so that we 

1. use the first template with the auto lambda to deduce types just in time
2. use the second template to extract the appropriate types to materialize the result

The next static overload of the ```do_map``` function allows an output container type to be specified. This function is simply a rearrangement of the template arguments so ```CC``` can go first and thus be explicitly specified by a caller. Since both templates are available, if ```CC``` is not explicitly specified [SFINAE](http://en.cppreference.com/w/cpp/language/sfinae) kicks in and the compiler will choose the template above instead.

```c++
template < 
  template <typename, typename...> class CC,
  typename A,
  typename F, 
  template <typename, typename...> class C,
  typename ...AT
>
auto
do_map (C<A,AT...> & c, F f) 
{
  return do_map<A, F, C, CC, AT...>(c, f);
}
```


Finally an only slightly less trivial example

```c++
struct Plant { string name; size_t quantity; };
using Landscape = vector<Plant>;

Landscape yard
{
  {"tulip", 150},
  {"weed", 62},
  {"tomato", 47},
  {"basil", 55},
  {"rose", 15}
};

auto garden =
  yard  //start with a slightly janky yard
  | filter( [](Plant p){ return p.name == "weed"; } ) //pick the weeds
  | map( [](Plant p){ p.quantity *= 1.5; return p; } ) //grow
  | map( [](Plant p){ 
      return p.name + "(" + to_string(p.quantity) + ")"; } ) //plant -> str
  | reduce( [](string x, string y){ return x + "\n" + y; }) //[str] -> str
  ;    //end with a beautiful garden

cout << garden << endl;
```
```bash
$ ./run
tulip(225)
tomato(70)
basil(82)
rose(22)
```

Check out the code [on GitHub](https://github.com/rcgoodfellow/pipes) for more.
