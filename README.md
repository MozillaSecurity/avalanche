# Avalanche

[![Build Status](https://api.travis-ci.com/MozillaSecurity/avalanche.svg)](https://travis-ci.com/MozillaSecurity/avalanche)
[![codecov](https://codecov.io/gh/MozillaSecurity/avalanche/branch/master/graph/badge.svg)](https://codecov.io/gh/MozillaSecurity/avalanche)


Avalanche is a document generator which uses context-free grammars to generate
randomized outputs for fuzz-testing.  See the examples folder for some working
grammars.


## Quickstart

Define your grammar in a text file (UTF-8 encoding). 'root' is the default start symbol.

###### Example my.gmr:
```
root            "<html>\n" \
                "<body>\n" \
                content{10} \
                "</body>\n" \
                "</html>"

content         "<" (tagname) ' style="color:' colour ';">Hello world</' @1 ">\n"

color           "#" /[a-f0-9]{3}/

tagname     1   "b"
            1   "blink"
            1   "i"
            1   "marquee"
            1   "span"
```

###### How to generate:
```
with open('my.gmr') as fd:
    g = Grammar(fd)
result = g.generate()
```

###### Example value of `result` from the above grammar:
```
<html>
<body>
<i style="color:#8b2;">Hello world</i>
<marquee style="color:#d09;">Hello world</marquee>
<b style="color:#aa9;">Hello world</b>
<b style="color:#93d;">Hello world</b>
<b style="color:#ada;">Hello world</b>
<span style="color:#464;">Hello world</span>
<span style="color:#90f;">Hello world</span>
<blink style="color:#ee9;">Hello world</blink>
<marquee style="color:#661;">Hello world</marquee>
<i style="color:#a21;">Hello world</i>
</body>
</html>
```


## Syntax Cheatsheet

```
# TextSymbol
SymName         "text"          # generate u"text" in the output

# ChoiceSymbol
SymName   .5    Defn1           # choose between generating Defn1 (1:3 odds)
          1     Defn2           #                        or Defn2 (2:3 odds)

SymName2  +     SymName         # '+' imports choices & weights from SymName into SymName2
          1     Defn3           #   ie. choices are Defn1 (1:5), Defn2 (2:5) or Defn3 (1:5)

SymName3        (SubSym1 | SubSym2)  # inline choice, SubSym1 & SubSym2 are generated equally
                                     # this is also a grouping and can be repeated.

# ConcatSymbol
SymName         SubSym1 SubSym2             # concat, generate SubSym1 then SubSym2
SymName         SubSym1 ( SubSym2 SubSym3 ) # inline concat (grouping), SubSym2 & SubSym3 can be
                                            #   repeated using RepeatSymbol or referenced later in
                                            #   the same line using RefSymbol

# RepeatSymbol
SymName         SubSym{a,b}     # repeat SubSym a random number of times, between a and b
SymName         SubSym{a}       # repeat SubSym 'a' times
SymName         SubSym?         # shorthand for {0,1}
# RepeatSampleSymbol
SymName         SubSym<a,b>     # repeatedly generate SubSym between [a,b] unique choices
                                #   SubSym must be a choice or a concat containing exactly
                                #   one choice

# RegexSymbol
SymName         /[A-Za-z]{0,4}..?[^a-f]{2}/  # simple regex generator, generate from A-Za-z [0,4]
                                             # times, '.' generates printable ASCII. [^] inverts
                                             # characters. ? generates [0,1] instances, etc.
                                             # Unicode ranges are supported.

# RefSymbol
SymName         @SymName2       # returns a previously generated instance of SymName2
SymName         ('abc') @1      # returns the value generated in a previous ConcatSymbol defined in the
                                #   same line (numbered in order of opening bracket, starting at 1)

# FuncSymbol
SymName         rndint(a,b)     # rndint, rndflt, rndpow2, eval, id, push, pop are built-in,
                                #   others can be passed as keyword args to the Grammar constructor
                                #   args can be numeric literals, or symbol definitions

# Import
Blah            import('another.gmr')    # can use imported symnames like Blah.SymName
```


## About the name

Avalanche is French for "Avalanche".
