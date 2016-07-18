Avalanche
=========

[![Build Status](https://api.travis-ci.org/jschwartzentruber/avalanche.svg)](https://travis-ci.org/jschwartzentruber/avalanche)

Avalanche is a document generator which uses context-free grammars to generate
randomized outputs for fuzz-testing.


Syntax Cheatsheet
-----------------

```
SymName         Def1 [Def2] (concat)
SymName{a,b}    Def (repeat, between a-b instances)
SymName   1     Def1 (choice, either Def1 (1:3 odds) or Def2 (2:3))
          2     Def2
SymName         /[A-Za-z]*..+[^a-f]{2}/ (simple regex)
SymName         "text"
SymName         @SymName1   (returns a previously defined instance of SymName1)
FuncCall        rndint(a,b) (rndint, rndflt are built-in,
                             others can be passed as keyword args to the Grammar constructor)
SymName<a,b>    ChoiceDef (combine repeat and choice, but each defn will only be used at most once)
Blah            import('another.gmr')    (can use imported symnames like Blah.SymName)
SymName         Def1 ( 'A' 'B' )? (grouping, 'A' & 'B' will be generated 0 or 1 times)
```


Quickstart
----------

Define your grammar in a text file (UTF-8 encoding). 'root' is the default start symbol.

```
with open('my.gmr') as fd:
    g = Grammar(fd)
result = g.generate()
```


About the name
--------------

Avalanche is French for "Avalanche".

