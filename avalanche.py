################################################################################
# coding=utf-8
# pylint: disable=missing-docstring,too-many-lines
#
# Description: Grammar based generation/fuzzer
# Author: Jesse Schwartzentruber
#
# Portions Copyright 2014 BlackBerry Limited
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#    http://www.apache.org/licenses/LICENSE-2.0
#
#    Unless required by applicable law or agreed to in writing, software
#    distributed under the License is distributed on an "AS IS" BASIS,
#    WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
#    See the License for the specific language governing permissions and
#    limitations under the License.
################################################################################
# Language Defn Syntax
# ====================
#
# SymName         Def1 [Def2] (concat)
# SymName{a,b}    Def (repeat, between a-b instances)
# SymName   1     Def1 (choice, either Def1 (1:3 odds) or Def2 (2:3))
#           2     Def2
# SymName         /[A-Za-z]*..+[^a-f]{2}/ (simple regex)
# SymName         "text"
# SymName         @SymName1   (returns a previously defined instance of SymName1)
# FuncCall        rndint(a,b) (rndint, rndflt are built-in,
#                              others can be passed as keyword args to the Grammar constructor)
# SymName<a,b>    ChoiceDef (combine repeat and choice, but each defn will only be used at most once)
# Blah            import('another.gmr')    (can use imported symnames like Blah.SymName)
################################################################################

from __future__ import unicode_literals
import argparse
import binascii
import hashlib
import io
import logging as log
import numbers
import os
import os.path
import random
import re
import sys


__all__ = ("Grammar", "GrammarException", "ParseError", "IntegrityError", "GenerationError", "WeightedChoice",
           "BinSymbol", "ChoiceSymbol", "ConcatSymbol", "FuncSymbol", "RefSymbol", "RepeatSymbol",
           "RepeatSampleSymbol", "RegexSymbol", "TextSymbol")


if sys.version_info.major == 2:
    # pylint: disable=redefined-builtin,invalid-name
    str = unicode


DEFAULT_LIMIT = 100 * 1024

if bool(os.getenv("DEBUG")):
    log.getLogger().setLevel(log.DEBUG)


class GrammarException(Exception):
    def __str__(self):
        if len(self.args) == 2:
            msg, state = self.args
            if isinstance(state, _ParseState):
                return "%s (%sline %d)" % (msg, "%s " % state.name if state.name else "", state.line_no)
            if isinstance(state, _GenState):
                return "%s (generation backtrace: %s)" % (msg, state.backtrace())
            return "%s (line %d)" % (msg, state) # state is line_no in this case
        if len(self.args) == 1:
            return str(self.args[0])
        return str(self.args)
class ParseError(GrammarException):
    pass
class IntegrityError(GrammarException):
    pass
class GenerationError(GrammarException):
    pass


class _GenState(object):

    def __init__(self, grmr):
        self.symstack = []
        self.instances = {}
        self.output = []
        self.grmr = grmr
        self.length = 0

    def append(self, value):
        if self.output and not isinstance(value, type(self.output[0])):
            raise GenerationError("Wrong value type generated, expecting %s, got %s" % (type(self.output[0]).__name__,
                                                                                        type(value).__name__), self)
        self.output.append(value)
        self.length += len(value)

    def backtrace(self):
        return ", ".join(sym[1] for sym in self.symstack
                         if isinstance(sym, tuple) and sym[0] == 'unwind')


class _ParseState(object):

    def __init__(self, prefix, grmr, filename):
        self.prefix = prefix
        self.imports = {} # friendly name -> (grammar hash, import line_no)
        self.imports_used = set() # friendly names used by get_prefixed()
        self.line_no = 0
        self.n_implicit = -1
        self.grmr = grmr
        self.name = filename

    def implicit(self):
        self.n_implicit += 1
        return self.n_implicit

    def get_prefixed(self, symprefix, sym):
        if symprefix:
            symprefix = symprefix[:-1]
            try:
                newprefix = self.imports[symprefix][0]
                self.imports_used.add(symprefix)
                symprefix = newprefix
            except KeyError:
                raise ParseError("Attempt to use symbol from unknown prefix: %s" % symprefix, self)
        else:
            symprefix = self.prefix
        return "%s.%s" % (symprefix, sym)

    def add_import(self, name, grammar_hash):
        self.imports[name] = (grammar_hash, self.line_no)

    def sanity_check(self):
        unused = set(self.imports) - self.imports_used
        if unused:
            raise IntegrityError("Unused import%s: %s" % ("s" if len(unused) > 1 else "", list(unused)), self)


class WeightedChoice(object):

    def __init__(self, iterable=None):
        self.total = 0.0
        self.values = []
        self.weights = []
        if iterable is not None:
            self.extend(iterable)

    def extend(self, iterable):
        for value in iterable:
            self.append(*value)

    def append(self, value, weight):
        self.total += weight
        self.values.append(value)
        self.weights.append(weight)

    def choice(self):
        target = random.uniform(0, self.total)
        for weight, value in zip(self.weights, self.values):
            target -= weight
            if target < 0:
                return value
        raise AssertionError("Too much total weight? remainder is %0.2f from %0.2f total" % (target, self.total))

    def sample(self, k):
        weights, values, total = self.weights[:], self.values[:], self.total
        result = []
        while k and total:
            target = random.uniform(0, total)
            for i, (weight, value) in enumerate(zip(weights, values)):
                target -= weight
                if target < 0:
                    result.append(value)
                    total -= weight
                    k -= 1
                    del weights[i]
                    del values[i]
                    break
            else:
                raise AssertionError("Too much total weight? remainder is %0.2f from %0.2f total" % (target, total))
        return result

    def __repr__(self):
        return "WeightedChoice(%s)" % list(zip(self.values, self.weights))


class Grammar(object):
    """Generate a language conforming to a given grammar specification.

    A Grammar consists of a set of symbol definitions which are used to define the structure of a language. The Grammar
    object is created from a text input with the format described below, and then used to generate randomly constructed
    instances of the described language. The entrypoint of the grammar is the named symbol 'root'. Comments are allowed
    anywhere in the file, preceded by a hash character (``#``).

    Symbols can either be named or implicit. A named symbol consists of a symbol name at the beginning of a line,
    followed by at least one whitespace character, followed by the symbol definition.

        ::

            SymbolName  Definition

    Implicit symbols are defined without being assigned an explicit name. For example a regular expression can be used
    in a concatenation definition directly, without being assigned a name. Choice and repeat symbols cannot be defined
    implicitly.

    **Concatenation**:

            ::

                SymbolName      SubSymbol1 [SubSymbol2] ...

        A concatenation consists of one or more symbols which will be generated in succession. The sub-symbol can be
        any named symbol, reference, or an implicit declaration of allowed symbol types. A concatenation can also be
        implicitly defined as the sub-symbol of a choice or repeat symbol.

    **Choice**: (must be named, not implicit)

            ::

                SymbolName      Weight1     SubSymbol1
                               [Weight2     SubSymbol2]
                               [Weight3     SubSymbol3]

        A choice consists of one or more weighted sub-symbols. At generation, only one of the sub-symbols will be
        generated at random, with each sub-symbol being generated with probability of weight/sum(weights) (the sum of
        all weights in this choice). Weight can be a non-negative number.

    **Repeat**: (must be named, not implicit)

            ::

                SymbolName      {Min,Max}   SubSymbol

        Defines a repetition of a sub-symbol. The number of repetitions is at most ``Max``, and at minimum ``Min``.

    **Repeat Unique**: (must be named, not implicit)

            ::

                SymbolName      <Min,Max>   SubSymbol

        Defines a repetition of a sub-symbol. The number of repetitions is at most ``Max``, and at minimum ``Min``.
        The sub-symbol must be a single ``ChoiceSymbol``, and the generated repetitions will be unique from the
        choices in the sub-symbol.

    **Text**:

            ::

                SymbolName      'some text'
                SymbolName      "some text"

        A text symbol is a string generated verbatim in the output. A few escape codes are recognized:
            * ``\\t``  horizontal tab (ASCII 0x09)
            * ``\\n``   line feed (ASCII 0x0A)
            * ``\\v``  vertical tab (ASCII 0x0B)
            * ``\\r``  carriage return (ASCII 0x0D)
        Any other character preceded by backslash will appear in the output without the backslash (including backslash,
        single quote, and double quote).

    **Regular expression**:

            ::

                SymbolName      /[a-zA][0-9]*.+[^0-9]{2}.[^abc]{1,3}/

        A regular expression (regex) symbol is a minimal regular expression implementation used for generating text
        patterns (rather than the traditional use for matching text patterns). A regex symbol consists of one or more
        parts in succession, and each part consists of a character set definition optionally followed by a repetition
        specification. The character set definition can be a period ``.`` to denote any character, a set of characters
        in brackets eg. ``[0-9a-f]``, or an inverted set of characters ``[^a-z]`` (any character except a-z). As shown,
        ranges can be used by using a dash. The dash character can be matched in a set by putting it last in the
        brackets. The optional repetition specification can be a range of integers in curly braces, eg. ``{1,10}`` will
        generate between 1 and 10 repetitions (at random), a single integer in curly braces, eg. ``{10}`` will generate
        exactly 10 repetitions, an asterisk character (``*``) which is equivalent to ``{0,5}``, or a plus character
        (``+``) which is equivalent to ``{1,5}``.

    **Random floating point decimal**:

            ::

                SymbolName      rndflt(a,b)

        A random floating-point decimal number between ``a`` and ``b`` inclusive.

    **Random integer**:

            ::

                SymbolName      rndint(a,b)

        A random integer between ``a`` and ``b`` inclusive.

    **Random integer near power of 2**

            ::

                SymbolName      rndpow2(exponent_limit, variation)

        This function is intended to return edge values around powers of 2. It is equivalent to:
        ``pow(2, rndint(0, exponent_limit)) + rndint(-variation, variation)``

    **Reference**:

            ::

                SymbolRef       @SymbolName

        Symbol references allow a generated symbol to be used elsewhere in the grammar. Referencing a symbol by
        ``@Symbol`` will output a generated value of ``Symbol`` from elsewhere in the output.

    **Filter function**:

            ::

                SymbolName      function(SymbolArg1[,...])

        This denotes an externally defined filter function. Note that the function name can be any valid Python
        identifier. The function can take an arbitrary number of arguments, but must return a single string which is
        the generated value for this symbol instance. Functions are passed as keyword arguments into the Grammar object
        constructor.

    **Imports**:

            ::

                ModuleName  import("filename")

        Imports allow you to break up grammars into multiple files. A grammar which imports another assigns it a local
        name ``ModuleName``, which may be used to access symbols from that grammar such as ``ModuleName.Symbol``, etc.
        Everything should work as expected, including references. Modules must be imported before they can be used.

    """
    _RE_LINE = re.compile(r"""
                           ^(?P<broken>.*)\\$ |
                           ^\s*(?P<comment>\#).*$ |
                           ^(?P<nothing>\s*)$ |
                           ^(?P<name>[\w:-]+)
                                (?P<type>((?P<weight>\s+[\d.]+\s+)
                                          |\s*\{\s*(?P<a>\d+)\s*(,\s*(?P<b>\d+)\s*)?\}\s+
                                          |\s* <\s*(?P<c>\d+)\s*(,\s*(?P<d>\d+)\s*)? >\s+
                                          |\s+import\(\s*)
                                 |
                                 \s+)
                                (?P<def>.+)$ |
                           ^\s+((?P<contweight>[\d.]+))\s*(?P<cont>.+)$
                           """, re.VERBOSE)

    def __init__(self, grammar="", limit=DEFAULT_LIMIT, **kwargs):
        self._limit = limit
        self.symtab = {}
        self.tracked = set()
        self.funcs = kwargs
        if "rndint" not in self.funcs:
            self.funcs["rndint"] = lambda a, b: str(random.randint(int(a), int(b)))
        if "rndpow2" not in self.funcs:
            self.funcs["rndpow2"] = lambda a, b: str(2 ** random.randint(0, int(a)) + random.randint(-int(b), int(b)))
        if "rndflt" not in self.funcs:
            self.funcs["rndflt"] = lambda a, b: str(random.uniform(float(a), float(b)))
        if "import" in self.funcs:
            raise IntegrityError("'import' is a reserved function name")

        need_to_close = False
        if hasattr(grammar, "read"):
            if isinstance(grammar.read(1), bytes):
                # need to reopen as unicode
                grammar.seek(0)
                try:
                    grammar = open(grammar.name, 'r') # will fail if grammar is not a named file...
                    need_to_close = True
                except (AttributeError, IOError):
                    # can't reopen, no choice but to read the whole input
                    grammar = io.StringIO(grammar.read().decode("utf-8"))
        elif isinstance(grammar, bytes):
            grammar = io.StringIO(grammar.decode("utf-8"))
        else:
            grammar = io.StringIO(grammar)

        # Initial definitions use hash of the grammar as the prefix, keeping track of the first used friendly name
        # ("" for top level). When grammar and imports are fully parsed, do a final pass to rename hash prefixes to
        # friendly prefixes.

        imports = {} # hash -> friendly prefix
        try:
            self.parse(grammar, imports)
        finally:
            if need_to_close:
                grammar.close()
        self.reprefix(imports)
        self.sanity_check()

    def parse(self, grammar, imports, prefix=""):
        grammar_hash = hashlib.sha512()
        while True:
            hash_str = grammar.read(4096)
            grammar_hash.update(hash_str.encode("utf-8"))
            if len(hash_str) < 4096:
                break
        grammar_hash = grammar_hash.hexdigest()[:6]
        grammar_fn = getattr(grammar, "name", None)
        if grammar_hash in imports:
            return grammar_hash
        imports[grammar_hash] = prefix
        grammar.seek(0)
        pstate = _ParseState(grammar_hash, self, grammar_fn)

        sym = None
        ljoin = ""
        for line in grammar:
            pstate.line_no += 1
            pstate.n_implicit = -1
            log.debug("parsing line # %d: %s", pstate.line_no, line.rstrip())
            match = Grammar._RE_LINE.match("%s%s" % (ljoin, line))
            if match is None:
                raise ParseError("Failed to parse definition at: %s%s" % (ljoin, line.rstrip()), pstate)
            if match.group("broken") is not None:
                ljoin = match.group("broken")
                continue
            ljoin = ""
            if match.group("comment") or match.group("nothing") is not None:
                continue
            if match.group("name"):
                sym_name, sym_type, sym_def = match.group("name", "type", "def")
                sym_type = sym_type.lstrip()
                if match.group("weight"):
                    # choice
                    weight = float(match.group("weight"))
                    sym = ChoiceSymbol(sym_name, pstate)
                    sym.append(Symbol.parse(sym_def, pstate), weight)
                elif sym_type.startswith("{"):
                    # repeat
                    min_, max_ = match.group("a", "b")
                    min_ = int(min_)
                    max_ = int(max_) if max_ else min_
                    sym = RepeatSymbol(sym_name, min_, max_, pstate)
                    sym.extend(Symbol.parse(sym_def, pstate))
                elif sym_type.startswith("<"):
                    # repeat (unique)
                    min_, max_ = match.group("c", "d")
                    min_ = int(min_)
                    max_ = int(max_) if max_ else min_
                    sym = RepeatSampleSymbol(sym_name, min_, max_, pstate)
                    sym.extend(Symbol.parse(sym_def, pstate))
                elif sym_type.startswith("import("):
                    if "%s.%s" % (grammar_hash, sym_name) in self.symtab:
                        raise ParseError("Redefinition of symbol %s previously declared on line %d"
                                         % (sym_name, self.symtab["%s.%s" % (grammar_hash, sym_name)].line_no), pstate)
                    sym, defn = TextSymbol.parse(sym_def, pstate, no_add=True)
                    defn = defn.strip()
                    if not defn.startswith(")"):
                        raise ParseError("Expected ')' parsing import at: %s" % defn, pstate)
                    defn = defn[1:].lstrip()
                    if defn.startswith("#") or defn:
                        raise ParseError("Unexpected input following import: %s" % defn, pstate)
                    # resolve sym.value from current grammar path or "."
                    if grammar_fn is not None:
                        import_paths = [os.path.join(os.path.dirname(grammar_fn), sym.value), sym.value]
                    else:
                        import_paths = [sym.value]
                    for import_fn in import_paths:
                        try:
                            with open(import_fn) as import_fd:
                                pstate.add_import(sym_name, self.parse(import_fd, imports, prefix=sym_name))
                            break
                        except IOError:
                            pass
                    else:
                        raise IntegrityError("Could not find imported grammar: %s" % sym.value, pstate)
                else:
                    # sym def
                    sym = ConcatSymbol.parse(sym_name, sym_def, pstate)
            else:
                # continuation of choice
                if sym is None or not isinstance(sym, ChoiceSymbol):
                    raise ParseError("Unexpected continuation of choice symbol", pstate)
                weight = float(match.group("contweight"))
                sym.append(Symbol.parse(match.group("cont"), pstate), weight)

        pstate.sanity_check()
        return grammar_hash

    def reprefix(self, imports):
        def get_prefixed(symname):
            try:
                prefix, name = symname.split(".", 1)
            except ValueError:
                return symname
            ref = prefix.startswith("@")
            if ref:
                prefix = prefix[1:]
            try:
                newprefix = imports[prefix]
            except KeyError:
                raise ParseError("Failed to reassign %s to proper namespace after parsing" % symname)
            newname = "".join((newprefix, "." if newprefix else "", name))
            if symname != newname:
                log.debug('reprefixed %s -> %s', symname, newname)
            return "".join(("@" if ref else "", newname))

        # rename prefixes to friendly names
        for oldname in list(self.symtab):
            sym = self.symtab[oldname]
            assert oldname == sym.name
            newname = get_prefixed(oldname)
            if oldname != newname:
                sym.name = newname
                self.symtab[newname] = sym
                del self.symtab[oldname]
            sym.map(get_prefixed)
        self.tracked = {get_prefixed(t) for t in self.tracked}

    def sanity_check(self):
        log.debug("sanity checking symtab: %s", self.symtab)
        funcs_used = {"rndflt", "rndint", "rndpow2"}
        for sym in self.symtab.values():
            sym.sanity_check(self)
            if isinstance(sym, FuncSymbol):
                funcs_used.add(sym.fname)
        if set(self.funcs) != funcs_used:
            unused_kwds = tuple(set(self.funcs) - funcs_used)
            raise IntegrityError("Unused keyword argument%s: %s" % ("s" if len(unused_kwds) > 1 else "", unused_kwds))
        if "root" not in self.symtab:
            raise IntegrityError("Missing required start symbol: root")
        syms_used = {"root"}
        to_check = {"root"}
        checked = set()
        while to_check:
            sym = self.symtab[to_check.pop()]
            checked.add(sym.name)
            children = sym.children()
            log.debug("%s is %s with %d children %s", sym.name, type(sym).__name__, len(children), list(children))
            syms_used |= children
            to_check |= children - checked
        # ignore unused symbols that came from an import, Text, Regex, or Bin
        syms_ignored = {s for s in self.symtab if re.search(r"[.\[]", s)}
        unused_syms = list(set(self.symtab) - syms_used - syms_ignored)
        if unused_syms:
            raise IntegrityError("Unused symbol%s: %s" % ("s" if len(unused_syms) > 1 else "", unused_syms))
        # build paths to terminal symbols
        do_over = True
        while do_over:
            do_over = False
            for sym in self.symtab.values():
                if sym.can_terminate is None:
                    do_over = sym.update_can_terminate(self) or do_over
        for sym in self.symtab.values():
            if not (sym.can_terminate or any(self.symtab[child].can_terminate for child in sym.children())):
                raise IntegrityError("Symbol has no paths to termination (infinite recursion?): %s" % sym.name,
                                     sym.line_no)

    def is_limit_exceeded(self, length):
        return self._limit is not None and length >= self._limit

    def generate(self, start="root"):
        if not isinstance(start, _GenState):
            gstate = _GenState(self)
            gstate.symstack = [start]
            gstate.instances = {sym: [] for sym in self.tracked}
        else:
            gstate = start
        tracking = []
        while gstate.symstack:
            this = gstate.symstack.pop()
            if isinstance(this, tuple):
                if this[0] == 'unwind':
                    continue
                assert this[0] == "untrack", "Tracking mismatch: expected ('untrack', ...), got %r" % this
                tracked = tracking.pop()
                assert this[1] == tracked[0], "Tracking mismatch: expected '%s', got '%s'" % (tracked[0], this[1])
                instance = "".join(gstate.output[tracked[1]:])
                gstate.instances[this[1]].append(instance)
                continue
            if this in self.tracked: # need to capture everything generated by this symbol and add to "instances"
                gstate.symstack.append(("untrack", this))
                tracking.append((this, len(gstate.output)))
            gstate.symstack.append(('unwind', this))
            self.symtab[this].generate(gstate)
        try:
            return "".join(gstate.output)
        except TypeError:
            return b"".join(gstate.output)


class Symbol(object):
    _RE_DEFN = re.compile(r"""
                           ^(?P<quote>["']) |
                           ^(?P<hexstr>x["']) |
                           ^(?P<regex>/) |
                           ^(?P<infunc>[,)]) |
                           ^(?P<comment>\#).* |
                           ^(?P<func>\w+)\( |
                           ^@(?P<refprefix>[\w-]+\.)?(?P<ref>[\w:-]+) |
                           ^(?P<symprefix>[\w-]+\.)?(?P<sym>[\w:-]+) |
                           ^(?P<ws>\s+)""", re.VERBOSE)

    def __init__(self, name, pstate, no_add=False):
        if name == '%s.import' % pstate.prefix:
            raise ParseError("'import' is a reserved name", pstate)
        unprefixed = name.split(".", 1)[1]
        if unprefixed in pstate.imports:
            raise ParseError("Redefinition of symbol %s previously declared on line %d"
                             % (unprefixed, pstate.imports[unprefixed][1]), pstate)
        self.name = name
        self.line_no = pstate.line_no
        log.debug('\t%s %s', type(self).__name__.lower()[:-6], name)
        if not no_add:
            if name in pstate.grmr.symtab and not isinstance(pstate.grmr.symtab[name], (AbstractSymbol, RefSymbol)):
                unprefixed = name.split(".", 1)[1]
                raise ParseError("Redefinition of symbol %s previously declared on line %d"
                                 % (unprefixed, pstate.grmr.symtab[name].line_no), pstate)
            pstate.grmr.symtab[name] = self
        self.can_terminate = None

    def map(self, fcn):
        pass

    def sanity_check(self, grmr):
        pass

    def generate(self, gstate):
        raise GenerationError("Can't generate symbol %s of type %s" % (self.name, type(self)), gstate)

    def children(self):
        return set()

    def update_can_terminate(self, grmr):
        if all(grmr.symtab[c].can_terminate for c in self.children()):
            self.can_terminate = True
            return True
        return False

    @staticmethod
    def _parse(defn, pstate, in_func):
        result = []
        while defn:
            match = Symbol._RE_DEFN.match(defn)
            if match is None:
                raise ParseError("Failed to parse definition at: %s" % defn, pstate)
            log.debug("parsed %s from %s", {k: v for k, v in match.groupdict().items() if v is not None}, defn)
            if match.group("ws") is not None:
                defn = defn[match.end(0):]
                continue
            if match.group("quote"):
                sym, defn = TextSymbol.parse(defn, pstate)
            elif match.group("hexstr"):
                sym, defn = BinSymbol.parse(defn, pstate)
            elif match.group("regex"):
                sym, defn = RegexSymbol.parse(defn, pstate)
            elif match.group("func"):
                defn = defn[match.end(0):]
                sym, defn = FuncSymbol.parse(match.group("func"), defn, pstate)
            elif match.group("ref"):
                ref = pstate.get_prefixed(match.group("refprefix"), match.group("ref"))
                sym = RefSymbol(ref, pstate)
                defn = defn[match.end(0):]
            elif match.group("sym"):
                sym_name = pstate.get_prefixed(match.group("symprefix"), match.group("sym"))
                try:
                    sym = pstate.grmr.symtab[sym_name]
                except KeyError:
                    sym = AbstractSymbol(sym_name, pstate)
                defn = defn[match.end(0):]
            elif match.group("comment"):
                defn = ""
                break
            elif match.group("infunc"):
                if not in_func:
                    raise ParseError("Unexpected token in definition: %s" % defn, pstate)
                break
            result.append(sym.name)
        return result, defn

    @staticmethod
    def parse_func_arg(defn, pstate):
        return Symbol._parse(defn, pstate, True)

    @staticmethod
    def parse(defn, pstate):
        res, remain = Symbol._parse(defn, pstate, False)
        if remain:
            raise ParseError("Unexpected token in definition: %s" % remain, pstate)
        return res


class AbstractSymbol(Symbol):

    def __init__(self, name, pstate):
        Symbol.__init__(self, name, pstate)

    def sanity_check(self, grmr):
        raise IntegrityError("Symbol %s used but not defined" % self.name, self.line_no)


class BinSymbol(Symbol):
    _RE_QUOTE = re.compile(r'''(?P<end>["'])''')

    def __init__(self, value, pstate):
        name = "%s.[bin (line %d #%d)]" % (pstate.prefix, pstate.line_no, pstate.implicit())
        Symbol.__init__(self, name, pstate)
        try:
            self.value = binascii.unhexlify(value)
        except TypeError as err:
            raise ParseError("Invalid hex string: %s" % err, pstate)
        self.can_terminate = True

    def generate(self, gstate):
        gstate.append(self.value)

    @staticmethod
    def parse(defn, pstate):
        start, qchar, defn = defn[0], defn[1], defn[2:]
        if start != "x":
            raise ParseError("Error parsing binary string at: %s%s%s" % (start, qchar, defn), pstate)
        if qchar not in "'\"":
            raise ParseError("Error parsing binary string at: %s%s" % (qchar, defn), pstate)
        enquo = defn.find(qchar)
        if enquo == -1:
            raise ParseError("Unterminated bin literal!", pstate)
        value, defn = defn[:enquo], defn[enquo+1:]
        sym = BinSymbol(value, pstate)
        return sym, defn


class ChoiceSymbol(Symbol, WeightedChoice):

    def __init__(self, name, pstate, no_prefix=False):
        name = "%s.%s" % (pstate.prefix, name) if not no_prefix else name
        Symbol.__init__(self, name, pstate)
        WeightedChoice.__init__(self)
        self._choices_terminate = []

    def append(self, value, weight):
        WeightedChoice.append(self, value, weight)
        self._choices_terminate.append(None)

    def generate(self, gstate):
        try:
            if gstate.grmr.is_limit_exceeded(gstate.length) and self.can_terminate:
                terminators = WeightedChoice()
                for i in range(len(self.values)):
                    if self._choices_terminate[i]:
                        terminators.append(self.values[i], self.weights[i])
                gstate.symstack.extend(reversed(terminators.choice()))
            else:
                gstate.symstack.extend(reversed(self.choice()))
        except AssertionError as err:
            raise GenerationError(err, gstate)

    def children(self):
        children = set()
        for child in self.values:
            children |= set(child)
        return children

    def map(self, fcn):
        self.values = [[fcn(i) for i in j] for j in self.values]

    def update_can_terminate(self, grmr):
        for i, choice in enumerate(self.values):
            if all(grmr.symtab[child].can_terminate for child in choice):
                self._choices_terminate[i] = True
        if any(self._choices_terminate):
            self.can_terminate = True
            return True
        return False


class ConcatSymbol(Symbol, list):

    def __init__(self, name, pstate, no_prefix=False):
        name = "%s.%s" % (pstate.prefix, name) if not no_prefix else name
        Symbol.__init__(self, name, pstate)
        list.__init__(self)

    def children(self):
        return set(self)

    def map(self, fcn):
        list.__init__(self, [fcn(i) for i in self])

    def generate(self, gstate):
        gstate.symstack.extend(reversed(self))

    @staticmethod
    def parse(name, defn, pstate):
        result = ConcatSymbol(name, pstate)
        result.extend(Symbol.parse(defn, pstate))
        return result


class FuncSymbol(Symbol):

    def __init__(self, name, pstate):
        sname = "%s.[%s (line %d #%d)]" % (pstate.prefix, name, pstate.line_no, pstate.implicit())
        Symbol.__init__(self, sname, pstate)
        self.fname = name
        self.args = []

    def sanity_check(self, grmr):
        if self.fname not in grmr.funcs:
            raise IntegrityError("Function %s used but not defined" % self.fname, self.line_no)

    def generate(self, gstate):
        args = []
        for arg in self.args:
            if isinstance(arg, numbers.Number):
                args.append(arg)
            else:
                astate = _GenState(gstate.grmr)
                astate.symstack = [arg]
                astate.instances = gstate.instances
                args.append(gstate.grmr.generate(astate))
        gstate.append(gstate.grmr.funcs[self.fname](*args))

    def children(self):
        return set(a for a in self.args if not isinstance(a, numbers.Number))

    def map(self, fcn):
        _fcn = lambda x: x if isinstance(x, numbers.Number) else fcn(x)
        self.args = [_fcn(i) for i in self.args]

    @staticmethod
    def parse(name, defn, pstate):
        if name == "import":
            raise ParseError("'import' is a reserved function name", pstate)
        result = FuncSymbol(name, pstate)
        done = False
        while not done:
            arg, defn = Symbol.parse_func_arg(defn, pstate)
            if defn[0] not in ",)":
                raise ParseError("Expected , or ) parsing function args at: %s" % defn, pstate)
            done = defn[0] == ")"
            defn = defn[1:]
            if arg or not done:
                numeric_arg = False
                if len(arg) == 1 and isinstance(pstate.grmr.symtab[arg[0]], AbstractSymbol):
                    arg0 = arg[0].split(".", 1)[1]
                    for numtype in (int, float):
                        try:
                            value = numtype(arg0)
                            result.args.append(value)
                            del pstate.grmr.symtab[arg[0]]
                            numeric_arg = True
                            break
                        except ValueError:
                            pass
                if not numeric_arg:
                    sym = ConcatSymbol("%s.%s]" % (result.name[:-1], len(result.args)), pstate, no_prefix=True)
                    sym.extend(arg)
                    result.args.append(sym.name)
        return result, defn


class RefSymbol(Symbol):

    def __init__(self, ref, pstate):
        Symbol.__init__(self, "@%s" % ref, pstate)
        if ref not in pstate.grmr.symtab:
            pstate.grmr.symtab[ref] = AbstractSymbol(ref, pstate)
        self.ref = ref
        pstate.grmr.tracked.add(ref)

    def generate(self, gstate):
        if gstate.instances[self.ref]:
            gstate.append(random.choice(gstate.instances[self.ref]))
        else:
            log.debug("No instances of %s yet, generating one instead of a reference", self.ref)
            gstate.grmr.symtab[self.ref].generate(gstate)

    def children(self):
        return {self.ref}

    def map(self, fcn):
        self.ref = fcn(self.ref)


class RegexSymbol(ConcatSymbol):
    _REGEX_ALPHABET = "ABCDEFGHIJKLMNOPQRSTUVWXYZ" \
                      "abcdefghijklmnopqrstuvwxyz" \
                      "0123456789" \
                      ",./<>?;':\"[]\\{}|=_+`~!@#$%^&*() -"
    _RE_REPEAT = re.compile(r"^\{\s*(?P<a>\d+)\s*(,\s*(?P<b>\d+)\s*)?\}")

    def __init__(self, pstate):
        name = "%s.[regex (line %d #%d)]" % (pstate.prefix, pstate.line_no, pstate.implicit())
        ConcatSymbol.__init__(self, name, pstate, no_prefix=True)
        self.can_terminate = True

    def new_choice(self, n_implicit, pstate):
        name = "%s.%d]" % (self.name[:-1], n_implicit)
        return ChoiceSymbol(name, pstate, no_prefix=True)

    def add_repeat(self, sym, min_, max_, n_implicit, pstate):
        name = "%s.%d]" % (self.name[:-1], n_implicit)
        rep = RepeatSymbol(name, min_, max_, pstate, no_prefix=True)
        rep.append(sym.name)
        self.append(name)

    @staticmethod
    def parse(defn, pstate):
        result = RegexSymbol(pstate)
        n_implicit = 0
        char = 1
        sym = None
        if defn[0] != "/":
            raise ParseError("Regex definitions must begin with /", pstate)
        while char < len(defn):
            if defn[char] == "/":
                if sym is not None:
                    result.append(sym.name)
                return result, defn[char + 1:]
            elif defn[char] == "[":
                # range
                if sym is not None:
                    result.append(sym.name)
                sym = result.new_choice(n_implicit, pstate)
                n_implicit += 1
                inverse = defn[char + 1] == "^"
                char += 2 if inverse else 1
                alpha = []
                while char < len(defn):
                    if defn[char] == "\\":
                        alpha.append(defn[char + 1])
                        char += 2
                    elif defn[char] == "]":
                        char += 1
                        break
                    else:
                        alpha.append(defn[char])
                        char += 1
                    if len(alpha) >= 3 and alpha[-2] == "-":
                        # expand range
                        start, end, alpha = alpha[-3], alpha[-1], alpha[:-3]
                        alpha.extend(chr(letter) for letter in range(ord(start), ord(end)+1))
                        if alpha[-1] == "-": # move this so we don't end up expanding a false range
                                             # (not a bullet-proof solution?)
                            alpha = alpha[-1] + alpha[:-1]
                else:
                    break
                alpha = set(alpha)
                if inverse:
                    alpha = set(RegexSymbol._REGEX_ALPHABET) - alpha
                for letter in alpha:
                    sym.append([TextSymbol(letter, pstate).name], 1)
            elif defn[char] == ".":
                # any one thing
                if sym is not None:
                    result.append(sym.name)
                char += 1
                try:
                    sym = pstate.grmr.symtab["[regex alpha]"]
                except KeyError:
                    sym = ChoiceSymbol("[regex alpha]", pstate, no_prefix=True)
                    sym.line_no = 0
                    for letter in RegexSymbol._REGEX_ALPHABET:
                        sym.append([TextSymbol(letter, pstate, no_prefix=True).name], 1)
                        sym.values[-1][0].line_no = 0
            elif defn[char] == "\\":
                # escape
                if sym is not None:
                    result.append(sym.name)
                sym = TextSymbol(defn[char + 1], pstate)
                char += 2
            elif defn[char] == "+":
                if sym is None:
                    raise ParseError("Error parsing regex, unexpected + at: %s" % defn[char:], pstate)
                char += 1
                result.add_repeat(sym, 1, 5, n_implicit, pstate)
                n_implicit += 1
                sym = None
            elif defn[char] == "*":
                if sym is None:
                    raise ParseError("Error parsing regex, unexpected * at: %s" % defn[char:], pstate)
                result.add_repeat(sym, 0, 5, n_implicit, pstate)
                n_implicit += 1
                char += 1
                sym = None
            elif defn[char] == "{":
                if sym is None:
                    raise ParseError("Error parsing regex, unexpected { at: %s" % defn[char:], pstate)
                match = RegexSymbol._RE_REPEAT.match(defn[char:])
                if match is None:
                    raise ParseError("Error parsing regex, expecting {n} or {a,b} at: %s" % defn[char:], pstate)
                min_ = int(match.group("a"))
                max_ = int(match.group("b")) if match.group("b") else min_
                result.add_repeat(sym, min_, max_, n_implicit, pstate)
                n_implicit += 1
                char += match.end(0)
                sym = None
            else:
                # bare char
                if sym is not None:
                    result.append(sym.name)
                sym = TextSymbol(defn[char], pstate)
                char += 1
        raise ParseError("Unterminated regular expression", pstate)


class RepeatSymbol(ConcatSymbol):

    def __init__(self, name, min_, max_, pstate, no_prefix=False):
        name = "%s.%s" % (pstate.prefix, name) if not no_prefix else name
        ConcatSymbol.__init__(self, name, pstate, no_prefix=True)
        self.min_, self.max_ = min_, max_

    def generate(self, gstate):
        if gstate.grmr.is_limit_exceeded(gstate.length):
            if not self.can_terminate:
                return # chop the output. this isn't great, but not much choice
            reps = self.min_
        else:
            reps = random.randint(self.min_, random.randint(self.min_, self.max_)) # roughly betavariate(0.75, 2.25)
        gstate.symstack.extend(reps * tuple(reversed(self)))


class RepeatSampleSymbol(RepeatSymbol):

    def sanity_check(self, grmr):
        if len(self) != 1:
            raise IntegrityError("RepeatSampleSymbol %s can only have one child, got %d"
                                 % (self.name, len(self)), self.line_no)
        if not isinstance(grmr.symtab[self[0]], ChoiceSymbol):
            raise IntegrityError("RepeatSampleSymbol %s child must be a ChoiceSymbol, got %s(%s)"
                                 % (self.name, type(grmr.symtab[self[0]]).__name__, self[0]), self.line_no)

    def generate(self, gstate):
        if gstate.grmr.is_limit_exceeded(gstate.length):
            if not self.can_terminate:
                return # chop the output. this isn't great, but not much choice
            reps = self.min_
        else:
            reps = random.randint(self.min_, random.randint(self.min_, self.max_)) # roughly betavariate(0.75, 2.25)
        try:
            for selection in reversed(gstate.grmr.symtab[self[0]].sample(reps)):
                gstate.symstack.extend(reversed(selection))
        except AssertionError as err:
            raise GenerationError(err, gstate)


class TextSymbol(Symbol):
    _RE_QUOTE = re.compile(r'''(?P<end>["'])|\\(?P<esc>.)''')

    def __init__(self, value, pstate, no_prefix=False, no_add=False):
        name = "[text (line %d #%d)]" % (pstate.line_no, pstate.implicit() if not no_add else -1)
        name = "%s.%s" % (pstate.prefix, name) if not no_prefix else name
        Symbol.__init__(self, name, pstate, no_add=no_add)
        self.value = str(value)
        self.can_terminate = True

    def generate(self, gstate):
        gstate.append(self.value)

    @staticmethod
    def parse(defn, pstate, no_add=False):
        qchar, defn = defn[0], defn[1:]
        if qchar not in "'\"":
            raise ParseError("Error parsing string, expected \" or ' at: %s%s" % (qchar, defn), pstate)
        out, last = [], 0
        for match in TextSymbol._RE_QUOTE.finditer(defn):
            out.append(defn[last:match.start(0)])
            last = match.end(0)
            if match.group("end") == qchar:
                break
            elif match.group("end"):
                out.append(match.group("end"))
            else:
                try:
                    out.append({"n": "\n",
                                "r": "\r",
                                "t": "\t",
                                "v": "\v"}[match.group("esc")])
                except KeyError:
                    out.append(match.group("esc"))
        else:
            raise ParseError("Unterminated string literal!", pstate)
        defn = defn[last:]
        sym = TextSymbol("".join(out), pstate, no_add=no_add)
        return sym, defn


def main():
    argp = argparse.ArgumentParser(description="Generate a testcase from a grammar")
    argp.add_argument("input", type=argparse.FileType('r'), help="Input grammar definition")
    argp.add_argument("output", type=argparse.FileType('w'), nargs="?", default=sys.stdout, help="Output testcase")
    argp.add_argument("-f", "--function", action="append", nargs=2, default=[],
                      help="Function used in the grammar (eg. -f filter lambda x:x.replace('x','y')")
    argp.add_argument("-l", "--limit", type=int, default=DEFAULT_LIMIT, help="Set a generation limit (roughly)")
    args = argp.parse_args()
    args.function = {func: eval(defn) for (func, defn) in args.function}
    args.output.write(Grammar(args.input, limit=args.limit, **args.function).generate())

