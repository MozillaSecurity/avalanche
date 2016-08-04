################################################################################
# coding=utf-8
# pylint: disable=missing-docstring,too-many-lines
#
# Description: Grammar based generation/fuzzer
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


__all__ = ("Grammar", "GrammarException", "ParseError", "IntegrityError", "GenerationError",
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
            if isinstance(state, _Symbol):
                state = state.line_no
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
        self.backrefs = []

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
        self.capture_groups = []

    def implicit(self):
        self.n_implicit += 1
        return self.n_implicit

    def get_prefixed(self, symprefix, sym):
        if symprefix:
            symprefix = symprefix[:-1] # strip trailing .
            try:
                newprefix = self.imports[symprefix][0]
                self.imports_used.add(symprefix)
                symprefix = newprefix
            except KeyError:
                try:
                    float("%s.%s" % (symprefix, sym))
                except ValueError:
                    raise ParseError("Attempt to use symbol from unknown prefix: %s" % symprefix, self)
                # it's a float .. let it through for now
                sym = "%s.%s" % (symprefix, sym)
                symprefix = self.prefix
        else:
            symprefix = self.prefix
        return "%s.%s" % (symprefix, sym)

    def add_import(self, name, grammar_hash):
        self.imports[name] = (grammar_hash, self.line_no)

    def sanity_check(self):
        unused = set(self.imports) - self.imports_used
        if unused:
            raise IntegrityError("Unused import%s: %s" % ("s" if len(unused) > 1 else "", list(unused)), self)


class Grammar(object):
    """Generate a language conforming to a given grammar specification.

       A Grammar consists of a set of symbol definitions which are used to define the structure of a language. The
       Grammar object is created from a text input with the format described below, and then used to generate randomly
       constructed instances of the described language. The entrypoint of the grammar is the named symbol 'root'.
       Comments are allowed anywhere in the file, preceded by a hash character (``#``).

       Symbols can either be named or implicit. A named symbol consists of a symbol name at the beginning of a line,
       followed by at least one whitespace character, followed by the symbol definition.

       ::

           SymbolName  Definition

       Implicit symbols are defined without being assigned an explicit name. For example a regular expression can be
       used in a concatenation definition directly, without being assigned a name. Choice symbols cannot be defined
       implicitly.

       ::

           ModuleName  import("filename")

       Imports allow you to break up grammars into multiple files. A grammar which imports another assigns it a local
       name ``ModuleName``, which may be used to access symbols from that grammar such as ``ModuleName.Symbol``, etc.
       Everything should work as expected, including references. Modules must be imported before they can be used.
    """
    _RE_LINE = re.compile(r"""^((?P<broken>.*)\\
                                |\s*(?P<comment>\#).*
                                |(?P<nothing>\s*)
                                |(?P<name>[\w:-]+)
                                 (?P<type>(?P<weight>\s+(\d*\.)?\d+(e-?\d+)?\s+)
                                  |\s*\+\s*
                                  |\s+import\(\s*
                                  |\s+)
                                 (?P<def>[^\s].*)
                                |\s+(\+|(?P<contweight>(\d*\.)?\d+(e-?\d+)?))\s*(?P<cont>.+))$
                           """, re.VERBOSE)

    def __init__(self, grammar, limit=DEFAULT_LIMIT, **kwargs):
        self._limit = limit
        self.symtab = {}
        self.tracked = set()
        self.funcs = kwargs
        if "rndint" not in self.funcs:
            self.funcs["rndint"] = lambda a, b: str(random.randint(int(a), int(b)))
        if "rndpow2" not in self.funcs:
            self.funcs["rndpow2"] = lambda a, b: str(max(2 ** random.randint(0, int(a))
                                                         + random.randint(-int(b), int(b)), 0))
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
            else:
                grammar.seek(0)
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
        self.normalize()
        self.check_termination()

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
        log.debug("parsing new grammar %r:%s", grammar_fn, grammar_hash)
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
            pstate.capture_groups = []
            ljoin = ""
            if match.group("comment") or match.group("nothing") is not None:
                continue
            if match.group("name"):
                sym_name, sym_type, sym_def = match.group("name", "type", "def")
                sym_type = sym_type.lstrip()
                if sym_type.startswith("+") or match.group("weight"):
                    # choice
                    weight = float(match.group("weight")) if match.group("weight") else "+"
                    sym = ChoiceSymbol(sym_name, pstate)
                    sym.append(_Symbol.parse(sym_def, pstate), weight, pstate)
                elif sym_type.startswith("import("):
                    # import
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
                    import_paths = [sym.value]
                    if grammar_fn is not None:
                        import_paths.insert(0, os.path.join(os.path.dirname(grammar_fn), sym.value))
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
                weight = float(match.group("contweight")) if match.group("contweight") else "+"
                sym.append(_Symbol.parse(match.group("cont"), pstate), weight, pstate)

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

    def normalize(self):
        # normalize symbol tree (remove implicit concats, etc.)
        for name in list(self.symtab):
            try:
                sym = self.symtab[name]
            except KeyError:
                continue # can happen if symbol is optimized out
            sym.normalize(self)

    def sanity_check(self):
        log.debug("sanity checking symtab: %s", self.symtab)
        log.debug("tracked symbols: %s", self.tracked)
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

    def check_termination(self):
        # build paths to terminal symbols
        do_over = True
        while do_over:
            do_over = False
            for sym in self.symtab.values():
                if sym.can_terminate is None:
                    do_over = sym.update_can_terminate(self) or do_over
        terminators = {sym for sym in self.symtab if self.symtab[sym].can_terminate}
        maybes = {sym: None for sym in set(self.symtab) - terminators}
        do_over = True
        while do_over:
            do_over = False
            for sym in maybes:
                if maybes[sym] is None:
                    if any(child in terminators or maybes[child] for child in self.symtab[sym].children()):
                        maybes[sym] = True
                        do_over = True
        nons = [sym for sym in maybes if not maybes[sym]]
        if nons:
            raise IntegrityError("Symbol has no paths to termination (infinite recursion?): %s" % nons[0],
                                 self.symtab[nons[0]].line_no)

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
                if this[0] == 'faketrack':
                    # means that someone like RepeatSampleSymbol has expanded a tracked symbol
                    # they will have generated the untrack tuple already, we just need to update `tracking` here.
                    tracking.append((this[1], len(gstate.output)))
                    continue
                if this[0] == 'resetbackref':
                    gstate.backrefs.pop()
                    continue
                assert this[0] == "untrack", "Tracking mismatch: expected ('untrack', ...), got %r" % this
                tracked = tracking.pop()
                assert this[1] == tracked[0], "Tracking mismatch: expected '%s', got '%s'" % (tracked[0], this[1])
                instance = "".join(gstate.output[tracked[1]:])
                if "[concat" in this[1]:
                    gstate.backrefs[-1].setdefault(this[1], []).append(instance)
                else:
                    gstate.instances[this[1]].append(instance)
                continue
            if this in self.tracked: # need to capture everything generated by this symbol and add to "instances"
                gstate.symstack.append(("untrack", this))
                tracking.append((this, len(gstate.output)))
            gstate.symstack.append(('unwind', this))
            if "[" not in this:
                gstate.symstack.append(("resetbackref",))
                gstate.backrefs.append({})
            try:
                self.symtab[this].generate(gstate)
            except GenerationError:
                raise
            except Exception as err:
                raise GenerationError("%s: %s" % (type(err).__name__, str(err)), gstate)
        try:
            return "".join(gstate.output)
        except TypeError:
            return b"".join(gstate.output)


class _Symbol(object):
    _RE_DEFN = re.compile(r"""^((?P<quote>["'])
                                |(?P<hexstr>x["'])
                                |(?P<regex>/)
                                |(?P<implconcat>\()
                                |(?P<infunc>[,)])
                                |(?P<comment>\#).*
                                |(?P<func>\w+)\(
                                |(?P<maybe>\?)
                                |(?P<repeat>[{<]\s*(?P<a>\d+|\*)\s*(,\s*(?P<b>\d+|\*)\s*)?[}>])
                                |@(?P<refprefix>[\w-]+\.)?(?P<ref>[\w:-]+)
                                |(?P<symprefix>[\w-]+\.)?(?P<sym>[\w:-]+)
                                |(?P<ws>\s+))""", re.VERBOSE)

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
            if name in pstate.grmr.symtab and not isinstance(pstate.grmr.symtab[name], (_AbstractSymbol, RefSymbol)):
                unprefixed = name.split(".", 1)[1]
                raise ParseError("Redefinition of symbol %s previously declared on line %d"
                                 % (unprefixed, pstate.grmr.symtab[name].line_no), pstate)
            pstate.grmr.symtab[name] = self
        self.can_terminate = None

    def map(self, fcn):
        pass

    def normalize(self, grmr):
        pass

    def sanity_check(self, grmr):
        pass

    def generate(self, gstate):
        raise GenerationError("Can't generate symbol %s of type %s" % (self.name, type(self)), gstate)

    def children(self):
        return set()

    def update_can_terminate(self, grmr):
        if all(grmr.symtab[c].can_terminate for c in self.children()):
            log.debug("%s can terminate", self.name)
            self.can_terminate = True
            return True
        return False

    @staticmethod
    def _parse(defn, pstate, in_func, in_concat):
        result = []
        while defn:
            match = _Symbol._RE_DEFN.match(defn)
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
                try:
                    backref = int(match.group("ref"))
                except ValueError:
                    pass
                else:
                    if match.group("refprefix"):
                        raise ParseError("Invalid reference syntax at: %s" % defn, pstate)
                    if not (1 <= backref <= len(pstate.capture_groups)) or pstate.capture_groups[backref - 1] is None:
                        raise IntegrityError("Invalid backreference at: %s" % defn, pstate)
                    ref = pstate.capture_groups[backref-1]
                sym = RefSymbol(ref, pstate)
                defn = defn[match.end(0):]
            elif match.group("sym"):
                sym_name = pstate.get_prefixed(match.group("symprefix"), match.group("sym"))
                try:
                    sym = pstate.grmr.symtab[sym_name]
                except KeyError:
                    sym = _AbstractSymbol(sym_name, pstate)
                defn = defn[match.end(0):]
            elif match.group("comment"):
                defn = ""
                break
            elif match.group("infunc"):
                if in_func or (in_concat and match.group("infunc") == ")"):
                    break
                raise ParseError("Unexpected token in definition: %s" % defn, pstate)
            elif match.group("implconcat"):
                capture = len(pstate.capture_groups)
                pstate.capture_groups.append(None)
                parts, defn = _Symbol._parse(defn[match.end(0):], pstate, False, True)
                if not defn.startswith(")"):
                    raise ParseError("Expecting ) at: %s" % defn, pstate)
                name = "[concat (line %d #%d)]" % (pstate.line_no, pstate.implicit())
                sym = ConcatSymbol(name, pstate)
                pstate.capture_groups[capture] = sym.name
                sym.extend(parts)
                defn = defn[1:]
            elif match.group("maybe") or match.group("repeat"):
                if not result:
                    raise ParseError("Unexpected token in definition: %s" % defn, pstate)
                if match.group("maybe"):
                    repeat = RepeatSymbol
                    min_, max_ = 0, 1
                else:
                    if {"{": "}", "<": ">"}[match.group(0)[0]] != match.group(0)[-1]:
                        raise ParseError("Repeat symbol mismatch at: %s" % defn, pstate)
                    repeat = {"{": RepeatSymbol, "<": RepeatSampleSymbol}[match.group(0)[0]]
                    min_ = "*" if match.group("a") == "*" else int(match.group("a"))
                    max_ = ("*" if match.group("b") == "*" else int(match.group("b"))) if match.group("b") else min_
                parts = result.pop()
                name = "[repeat (line %d #%d)]" % (pstate.line_no, pstate.implicit())
                sym = repeat(name, min_, max_, pstate)
                sym.append(parts)
                defn = defn[match.end(0):]
            result.append(sym.name)
        return result, defn

    @staticmethod
    def parse_func_arg(defn, pstate):
        return _Symbol._parse(defn, pstate, True, False)

    @staticmethod
    def parse(defn, pstate):
        res, remain = _Symbol._parse(defn, pstate, False, False)
        if remain:
            raise ParseError("Unexpected token in definition: %s" % remain, pstate)
        return res

    def choice_idx(self, parts, grmr):
        # given a set of symbols, return the index of the ChoiceSymbol
        # this will raise if parts does not contain exactly one ChoiceSymbol,
        # or if any other symbol is other than TextSymbol/BinSymbol
        choice_idx = None
        for i, child in enumerate(parts):
            if isinstance(grmr.symtab[child], ChoiceSymbol):
                if choice_idx is not None:
                    raise IntegrityError("Expecting exactly one ChoiceSymbol in %s (got more than one)" % self.name,
                                         self.line_no)
                choice_idx = i
        if choice_idx is None:
            raise IntegrityError("Expecting exactly one ChoiceSymbol in %s (got none)" % self.name, self.line_no)
        return choice_idx


class _AbstractSymbol(_Symbol):

    def __init__(self, name, pstate):
        _Symbol.__init__(self, name, pstate)

    def sanity_check(self, grmr):
        raise IntegrityError("Symbol %s used but not defined" % self.name, self.line_no)


class BinSymbol(_Symbol):
    """Binary data

       ::

           SymbolName      x'41414141'

       Defines a chunk of binary data encoded in hex notation. ``BinSymbol`` and ``TextSymbol`` cannot be combined in
       the output.
    """

    _RE_QUOTE = re.compile(r"""(?P<end>["'])""")

    def __init__(self, value, pstate):
        name = "%s.[bin (line %d #%d)]" % (pstate.prefix, pstate.line_no, pstate.implicit())
        _Symbol.__init__(self, name, pstate)
        try:
            self.value = binascii.unhexlify(value.encode("ascii"))
        except (UnicodeEncodeError, TypeError) as err:
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


class ChoiceSymbol(_Symbol):
    """Choose between several options

       ::

           SymbolName      Weight1     SubSymbol1
                          [Weight2     SubSymbol2]
                          [Weight3     SubSymbol3]

       A choice consists of one or more weighted sub-symbols. At generation, only one of the sub-symbols will be
       generated at random, with each sub-symbol being generated with probability of weight/sum(weights) (the sum of
       all weights in this choice). Weight is a decimal number in the range 0.0 to 1.0 inclusive.

       Weight can also be ``+``, which imports another ``ChoiceSymbol`` into this definition. SubSymbol must be another
       ``ChoiceSymbol`` (or a concatenation of one or more ``TextSymbol``s and exactly one ``ChoiceSymbol``).
    """

    def __init__(self, name, pstate=None):
        name = "%s.%s" % (pstate.prefix, name)
        _Symbol.__init__(self, name, pstate)
        self.total = 0.0
        self.values = []
        self.weights = []
        self._choices_terminate = []
        self.normalized = False

    def append(self, value, weight, pstate):
        if weight != '+':
            if not 0.0 <= weight <= 1.0:
                raise IntegrityError("Invalid weight value for choice: %.2f (expecting [0,1])" % weight, pstate)
            self.total += weight
        self.values.append(value)
        self.weights.append(weight)
        self._choices_terminate.append(None)

    def _internal_choice(self, total, used):
        target = random.uniform(0, total[0])
        for i, (weight, value) in enumerate(zip(self.weights, self.values)):
            if used[i]:
                continue
            target -= weight
            if target < 0.0:
                used[i] = True
                total[0] -= weight
                return value
        raise AssertionError("Too much total weight? remainder is %.2f from %.2f total" % (target, total[0]))

    def choice(self, whitelist=None):
        if whitelist is not None:
            assert len(whitelist) == len(self)
            blacklist = [not x for x in whitelist]
        else:
            blacklist = [False] * len(self)
        return self._internal_choice([self.total], blacklist)

    def sample(self, k):
        result, used, total = [], ([False] * len(self)), [self.total]
        for _ in range(k):
            if total[0] <= 0.0:
                break
            result.append(self._internal_choice(total, used))
        return result

    def normalize(self, grmr):
        if self.normalized:
            return
        self.normalized = True
        for i, (value, weight) in enumerate(zip(self.values, self.weights)):
            if weight == '+':
                if len(value) == 1 and isinstance(grmr.symtab[value[0]], ConcatSymbol):
                    children = grmr.symtab[value[0]]
                else:
                    children = value
                choice_idx = self.choice_idx(children, grmr)
                choice = grmr.symtab[children[choice_idx]]
                if any(weight == '+' for weight in choice.weights):
                    if choice.normalized:
                        # recursive definition
                        raise IntegrityError("Can't resolve weight for '+' in %s, expansion of '%s' causes unbounded "
                                             "recursion" % (self.name, choice.name), self.line_no + i)
                    choice.normalize(grmr) # resolve the child '+' first
                self.weights[i] = choice.total
                self.total += self.weights[i]

    def generate(self, gstate):
        try:
            if gstate.grmr.is_limit_exceeded(gstate.length) and self.can_terminate:
                gstate.symstack.extend(reversed(self.choice(whitelist=self._choices_terminate)))
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
            log.debug("%s can terminate", self.name)
            self.can_terminate = True
            return True
        return False

    def __len__(self):
        return len(self.values)

    def __repr__(self):
        return "ChoiceSymbol(%s)" % list(zip(self.values, self.weights))


class ConcatSymbol(_Symbol, list):
    """Concatenation of subsymbols

       ::

           SymbolName      SubSymbol1 [SubSymbol2] ...

       A concatenation consists of one or more symbols which will be generated in succession. The sub-symbol can be
       any named symbol, reference, or an implicit declaration of terminal symbol types. A concatenation can also be
       implicitly used as the sub-symbol of a ``ChoiceSymbol``, or inline using ``(`` and ``)``. eg::

           SymbolName      SubSymbol1 ( SubSymbol2 SubSymbol3 ) ...

       This is most useful for defining implicit repeats for some terms in the concatenation.
    """

    def __init__(self, name, pstate, no_prefix=False):
        name = "%s.%s" % (pstate.prefix, name) if not no_prefix else name
        _Symbol.__init__(self, name, pstate)
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
        result.extend(_Symbol.parse(defn, pstate))
        return result


class FuncSymbol(_Symbol):
    """Function

       ::

           SymbolName      function(SymbolArg1[,...])

       This denotes an externally defined function. The function name can be any valid Python identifier. It can
       accept an arbitrary number of arguments, but must return a single string which is the generated value for
       this symbol instance. Functions must be passed as keyword arguments into the Grammar object constructor.

       The following functions are built-in::

           rndflt(a,b)      A random floating-point decimal number between ``a`` and ``b`` inclusive.
           rndint(a,b)      A random integer between ``a`` and ``b`` inclusive.
           rndpow2(exponent_limit, variation)
                            This function is intended to return edge values around powers of 2. It is equivalent to:
                            ``pow(2, rndint(0, exponent_limit)) + rndint(-variation, variation)``
    """

    def __init__(self, name, pstate):
        sname = "%s.[%s (line %d #%d)]" % (pstate.prefix, name, pstate.line_no, pstate.implicit())
        _Symbol.__init__(self, sname, pstate)
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
                astate.backrefs = gstate.backrefs
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
            arg, defn = _Symbol.parse_func_arg(defn, pstate)
            if defn[0] not in ",)":
                raise ParseError("Expected , or ) parsing function args at: %s" % defn, pstate)
            done = defn[0] == ")"
            defn = defn[1:]
            if arg or not done:
                numeric_arg = False
                if len(arg) == 1 and isinstance(pstate.grmr.symtab[arg[0]], _AbstractSymbol):
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


class RefSymbol(_Symbol):
    """Reference an instance of another symbol

       ::

           SymbolRef       @SymbolName

       Symbol references allow a generated symbol to be used elsewhere in the grammar. Referencing a symbol by
       ``@Symbol`` will output a generated value of ``Symbol`` from elsewhere in the output.
   """

    def __init__(self, ref, pstate):
        _Symbol.__init__(self, "@%s" % ref, pstate)
        if ref not in pstate.grmr.symtab:
            pstate.grmr.symtab[ref] = _AbstractSymbol(ref, pstate)
        self.ref = ref
        pstate.grmr.tracked.add(ref)

    def generate(self, gstate):
        if "[concat" in self.ref:
            backrefs = gstate.backrefs[-1]
            try:
                gstate.append(random.choice(backrefs[self.ref]))
            except KeyError:
                raise GenerationError("No symbols generated yet for backreference", gstate)
        elif gstate.instances[self.ref]:
            gstate.append(random.choice(gstate.instances[self.ref]))
        else:
            log.debug("No instances of %s yet, generating one instead of a reference", self.ref)
            gstate.grmr.symtab[self.ref].generate(gstate)

    def children(self):
        return {self.ref}

    def map(self, fcn):
        self.ref = fcn(self.ref)


class RegexSymbol(ConcatSymbol):
    """Text generated by a regular expression

       ::

           SymbolName         /id[0-9]{4}/      (generates strings between 'id0000' and 'id9999')
           ...                /a?far/           (generates either 'far' or 'afar')

       A regular expression (regex) symbol is a minimal regular expression implementation used for generating text
       patterns (rather than the traditional use for matching text patterns). A regex symbol consists of one or more
       parts in succession, and each part consists of a character set definition optionally followed by a repetition
       specification.

       The character set definition can be a single character, a period ``.`` to denote any ASCII character, a set of
       characters in brackets eg. ``[0-9a-f]``, or an inverted set of characters ``[^a-z]`` (any character except
       a-z). As shown, ranges can be defined by using a dash. The dash character can be matched in a set by putting it
       first or last in the set. Escapes work as in TextSymbol using the backslash character.

       The optional repetition specification can be a range of integers in curly braces, eg. ``{1,10}`` will generate
       between 1 and 10 repetitions (at random), a single integer in curly braces, eg. ``{10}`` will generate exactly
       10 repetitions, or a question mark (``?``) which is equivalent to ``{0,1}``.

       A notable exclusion from ordinary regular expression implementations is groups using ``()`` or ``(a|b)``. This
       syntax is *not* supported in RegexSymbol. The characters "()|" have no special meaning and do not need to be
       escaped.
    """
    _REGEX_ALPHABET = "ABCDEFGHIJKLMNOPQRSTUVWXYZ" \
                      "abcdefghijklmnopqrstuvwxyz" \
                      "0123456789" \
                      ",./<>?;':\"[]\\{}|=_+`~!@#$%^&*() -"
    _RE_PARSE = re.compile(r"""^((?P<repeat>\{\s*(?P<a>\d+)\s*(,\s*(?P<b>\d+)\s*)?\}|\?)
                                 |(?P<set>\[\^?)
                                 |(?P<esc>\\.)
                                 |(?P<dot>\.)
                                 |(?P<done>/))""", re.VERBOSE)
    _RE_SET = re.compile(r"^(\]|-|\\?.)")

    def __init__(self, pstate):
        name = "%s.[regex (line %d #%d)]" % (pstate.prefix, pstate.line_no, pstate.implicit())
        ConcatSymbol.__init__(self, name, pstate, no_prefix=True)
        self.can_terminate = True

    def _impl_name(self, n_implicit):
        name = "%s.%d]" % (self.name[:-1], n_implicit[0])
        n_implicit[0] += 1
        return name

    def new_text(self, value, n_implicit, pstate):
        self.append(TextSymbol(self._impl_name(n_implicit), value, pstate, no_prefix=True).name)

    def new_textchoice(self, alpha, n_implicit, pstate):
        self.append(_TextChoiceSymbol(self._impl_name(n_implicit), alpha, pstate, no_prefix=True).name)

    def add_repeat(self, min_, max_, n_implicit, pstate):
        rep = RepeatSymbol(self._impl_name(n_implicit), min_, max_, pstate, no_prefix=True)
        rep.append(self.pop())
        self.append(rep.name)

    @staticmethod
    def parse(defn, pstate):
        result = RegexSymbol(pstate)
        n_implicit = [0]
        if defn[0] != "/":
            raise ParseError("Regex definitions must begin with /", pstate)
        defn = defn[1:]
        while defn:
            match = RegexSymbol._RE_PARSE.match(defn)
            if match is None:
                result.new_text(defn[0], n_implicit, pstate)
                defn = defn[1:]
            elif match.group("set"):
                inverse = len(match.group("set")) == 2
                defn = defn[match.end(0):]
                alpha = []
                in_range = False
                while defn:
                    match = RegexSymbol._RE_SET.match(defn)
                    if match.group(0) == "]":
                        if in_range:
                            alpha.append('-')
                        defn = defn[match.end(0):]
                        break
                    elif match.group(0) == "-":
                        if in_range or not alpha:
                            raise ParseError("Parse error in regex at: %s" % defn, pstate)
                        in_range = True
                    else:
                        if match.group(0).startswith("\\"):
                            alpha.append(TextSymbol.ESCAPES.get(match.group(0)[1], match.group(0)[1]))
                        else:
                            alpha.append(match.group(0))
                        if in_range:
                            start = ord(alpha[-2])
                            end = ord(alpha[-1]) + 1
                            if start >= end:
                                raise ParseError("Empty range in regex at: %s" % defn, pstate)
                            alpha.extend(chr(letter) for letter in range(ord(alpha[-2]), ord(alpha[-1]) + 1))
                            in_range = False
                    defn = defn[match.end(0):]
                else:
                    raise ParseError("Unterminated set in regex", pstate)
                alpha = set(alpha)
                if inverse:
                    alpha = set(RegexSymbol._REGEX_ALPHABET) - alpha
                result.new_textchoice("".join(alpha), n_implicit, pstate)
            elif match.group("done"):
                return result, defn[match.end(0):]
            elif match.group("dot"):
                try:
                    pstate.grmr.symtab["[regex alpha]"]
                except KeyError:
                    sym = _TextChoiceSymbol("[regex alpha]", RegexSymbol._REGEX_ALPHABET, pstate, no_prefix=True)
                    sym.line_no = 0
                result.append("[regex alpha]")
                defn = defn[match.end(0):]
            elif match.group("esc"):
                result.new_text(TextSymbol.ESCAPES.get(match.group(0)[1], match.group(0)[1]), n_implicit, pstate)
                defn = defn[match.end(0):]
            else: # repeat
                if not len(result) or isinstance(pstate.grmr.symtab[result[-1]], RepeatSymbol):
                    raise ParseError("Error parsing regex, unexpected repeat at: %s" % defn, pstate)
                if match.group("a"):
                    min_ = int(match.group("a"))
                    max_ = int(match.group("b")) if match.group("b") else min_
                else:
                    min_, max_ = 0, 1
                result.add_repeat(min_, max_, n_implicit, pstate)
                defn = defn[match.end(0):]
        raise ParseError("Unterminated regular expression", pstate)


class RepeatSymbol(ConcatSymbol):
    """Repeat subsymbols a random number of times.

       ::

           SymbolName      SubSymbol {Min,Max}
           SymbolName      SubSymbol {n}
           SymbolName      SubSymbol ?

       Defines a repetition of subsymbols. The number of repetitions is at most ``Max``, and at minimum ``Min``.
       The second parameter is optional, in which case exactly ``n`` will be generated. ``?`` is shorthand for
       {0,1}. ``*`` can also be used, which evaluates to the number of choices in SubSymbol (must be ``ChoiceSymbol``
       or concatenation of text with one ``ChoiceSymbol`` to use ``*``).
    """

    def __init__(self, name, min_, max_, pstate, no_prefix=False):
        name = "%s.%s" % (pstate.prefix, name) if not no_prefix else name
        ConcatSymbol.__init__(self, name, pstate, no_prefix=True)
        self.min_, self.max_ = min_, max_

    def normalize(self, grmr):
        children = self
        if len(self) == 1 and isinstance(grmr.symtab[self[0]], ConcatSymbol):
            # must deref the concat to look for choice
            if isinstance(self, RepeatSampleSymbol):
                self.in_concat = True
            children = grmr.symtab[self[0]]
            log.debug('choice for %s is nested in a concat', self.name)
        if isinstance(self, RepeatSampleSymbol) or self.min_ == "*" or self.max_ == "*":
            choice_idx = self.choice_idx(children, grmr)
            choice_len = len(grmr.symtab[children[choice_idx]])
            if isinstance(self, RepeatSampleSymbol):
                self.sample_idx = choice_idx
            if self.min_ == "*":
                self.min_ = choice_len
            if self.max_ == "*":
                self.max_ = choice_len
        if self.min_ > self.max_ or self.min_ < 0:
            raise IntegrityError("Invalid range for repeat in %s: [%d,%d]" % (self.name, self.min_, self.max_),
                                 self.line_no)

    def generate(self, gstate):
        if gstate.grmr.is_limit_exceeded(gstate.length):
            if not self.can_terminate:
                return # chop the output. this isn't great, but not much choice
            reps = self.min_
        else:
            reps = random.randint(self.min_, random.randint(self.min_, self.max_)) # roughly betavariate(0.75, 2.25)
        gstate.symstack.extend(reps * tuple(reversed(self)))

    def update_can_terminate(self, grmr):
        if _Symbol.update_can_terminate(self, grmr):
            return True
        if self.min_ == 0:
            self.can_terminate = True
            log.debug("%s can terminate", self.name)
            return True
        return False


class RepeatSampleSymbol(RepeatSymbol):
    """
     **Repeat Unique**:

            ::

                SymbolName      <Min,Max>   SubSymbol

        Defines a repetition of a sub-symbol. The number of repetitions is at most ``Max``, and at minimum ``Min``.
        The sub-symbol must be choosable, ie. a single ``ChoiceSymbol`` or concatenation with exactly one
        ``ChoiceSymbol``. The generated repetitions will be unique from the choices in the sub-symbol. ``*`` can also
        be used, which evaluates to the number of choices in the sub-symbol (must be ``ChoiceSymbol`` or concatenation
        of text with one ``ChoiceSymbol``).
    """

    def __init__(self, name, min_, max_, pstate, no_prefix=False):
        RepeatSymbol.__init__(self, name, min_, max_, pstate, no_prefix)
        self.in_concat = False
        self.sample_idx = None

    def generate(self, gstate):
        if gstate.grmr.is_limit_exceeded(gstate.length):
            if not self.can_terminate:
                return # chop the output. this isn't great, but not much choice
            reps = self.min_
        else:
            reps = random.randint(self.min_, random.randint(self.min_, self.max_)) # roughly betavariate(0.75, 2.25)
        children = self
        if self.in_concat:
            children = gstate.grmr.symtab[self[0]]
        pre = children[:self.sample_idx]
        post = children[self.sample_idx + 1:]
        choice = gstate.grmr.symtab[children[self.sample_idx]]
        # if either the concat (if any) or the choice are tracked, we need to force tracking instances we generate
        if self.in_concat and self[0] in gstate.grmr.tracked:
            pre.insert(0, ("faketrack", self[0]))
            post.append(("untrack", self[0]))
        if choice.name in gstate.grmr.tracked:
            pre.append(("faketrack", choice.name))
            post.insert(0, ("untrack", choice.name))
        try:
            for selection in reversed(gstate.grmr.symtab[children[self.sample_idx]].sample(reps)):
                gstate.symstack.extend(reversed(pre + selection + post))
        except AssertionError as err:
            raise GenerationError(err, gstate)


class TextSymbol(_Symbol):
    """Text string

       ::

           SymbolName      'some text'
           SymbolName      "some text"

       A text symbol is a string generated verbatim in the output. C escape codes are recognized:
           * ``\\0``  null (ASCII 0x00)
           * ``\\a``  bell (ASCII 0x07)
           * ``\\b``  backspace (ASCII 0x08)
           * ``\\t``  horizontal tab (ASCII 0x09)
           * ``\\n``  line feed (ASCII 0x0A)
           * ``\\v``  vertical tab (ASCII 0x0B)
           * ``\\f``  form feed (ASCII 0x0C)
           * ``\\r``  carriage return (ASCII 0x0D)
           * ``\\e``  escape (ASCII 0x1B)

       Any other character preceded by backslash will appear in the output without the backslash (including backslash,
       single quote, and double quote).
    """

    _RE_QUOTE = re.compile(r"""(?P<end>["'])|\\(?P<esc>.)""")
    ESCAPES = {"0": "\0", "a": "\a", "b": "\b", "t": "\t", "n": "\n", "v": "\v", "f": "\f", "r": "\r", "e": "\x1b"}

    def __init__(self, name, value, pstate, no_prefix=False, no_add=False):
        if name is None:
            name = "[text (line %d #%d)]" % (pstate.line_no, pstate.implicit() if not no_add else -1)
        name = "%s.%s" % (pstate.prefix, name) if not no_prefix else name
        _Symbol.__init__(self, name, pstate, no_add=no_add)
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
                out.append(TextSymbol.ESCAPES.get(match.group("esc"), match.group("esc")))
        else:
            raise ParseError("Unterminated string literal!", pstate)
        defn = defn[last:]
        sym = TextSymbol(None, "".join(out), pstate, no_add=no_add)
        return sym, defn


class _TextChoiceSymbol(TextSymbol):

    def generate(self, gstate):
        gstate.append(random.choice(self.value))


def main():

    class _SafeFileType(argparse.FileType):

        def __call__(self, string):
            if 'w' in self._mode and os.path.isfile(string):
                raise argparse.ArgumentTypeError("output file exists, not overwriting: %s" % string)
            return argparse.FileType.__call__(self, string)

    argp = argparse.ArgumentParser(description="Generate a testcase from a grammar")
    argp.add_argument("input", type=_SafeFileType('r'), help="Input grammar definition")
    argp.add_argument("output", type=_SafeFileType('w'), nargs="?", default=sys.stdout, help="Output testcase")
    argp.add_argument("-f", "--function", action="append", nargs=2, default=[],
                      help="Function used in the grammar (eg. -f filter lambda x:x.replace('x','y')")
    argp.add_argument("-l", "--limit", type=int, default=DEFAULT_LIMIT, help="Set a generation limit (roughly)")
    args = argp.parse_args()
    args.function = {func: eval(defn) for (func, defn) in args.function}
    args.output.write(Grammar(args.input, limit=args.limit, **args.function).generate())


if __name__ == "__main__":
    main()

