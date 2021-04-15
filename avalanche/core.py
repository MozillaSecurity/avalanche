#!/usr/bin/env python
# coding=utf-8
# pylint: disable=missing-docstring,too-many-lines
################################################################################
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
import codecs
import hashlib
import io
import logging
import numbers
import os
import os.path
import random
import re
import sys

from .error import GenerationError, GrammarException, IntegrityError, ParseError
from .splist import SparseList

__all__ = (
    "Grammar",
    "GrammarException",
    "ParseError",
    "IntegrityError",
    "GenerationError",
    "BinSymbol",
    "ChoiceSymbol",
    "ConcatSymbol",
    "FuncSymbol",
    "RefSymbol",
    "RepeatSymbol",
    "RepeatSampleSymbol",
    "RegexSymbol",
    "SparseList",
    "TextSymbol",
    "unichr_",
)


if sys.version_info.major == 2:
    # pylint: disable=redefined-builtin,invalid-name
    str = unicode
    if sys.maxunicode == 65535:
        unichr_ = lambda c: (br"\U%08x" % c).decode("unicode-escape")
    else:
        unichr_ = unichr
else:
    unichr_ = chr
utf8_reader = codecs.getreader("utf-8")


def _file_to_unicode(fd):
    if isinstance(fd.read(1), bytes):
        # need to reopen as unicode
        fd.seek(0)
        fd = utf8_reader(fd)
    else:
        fd.seek(0)
    return fd


DEFAULT_LIMIT = 100 * 1024


LOG = logging.getLogger("avalanche")
LOG.setLevel(logging.INFO)


class _GenState(object):
    def __init__(self, grmr):
        self.symstack = []
        self.instances = {}
        self.instance_backlog = {}
        self.output = []
        self.grmr = grmr
        self.length = 0
        self.backrefs = []
        self.choice_stack = {}
        self.recursive_syms = {}
        self.push_stack = []
        self.id = 0

    def append(self, value):
        if self.output and not isinstance(value, type(self.output[0])):
            raise GenerationError(
                "Wrong value type generated, expecting %s, got %s"
                % (type(self.output[0]).__name__, type(value).__name__)
            )
        self.output.append(value)
        self.length += len(value)

    def backtrace(self):
        return ", ".join(sym[1] for sym in self.symstack if sym[0] == "unwind")

    def generate_id(self):
        result = "%d" % self.id
        self.id += 1
        self.append(result)


class _ParseState(object):
    def __init__(self, prefix, grmr, filename):
        self.prefix = prefix
        self.imports = {}  # friendly name -> (grammar hash, import line_no)
        self.imports_used = set()  # friendly names used by get_prefixed()
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
            symprefix = symprefix[:-1]  # strip trailing .
            try:
                newprefix = self.imports[symprefix][0]
                self.imports_used.add(symprefix)
                symprefix = newprefix
            except KeyError:
                try:
                    float("%s.%s" % (symprefix, sym))
                except ValueError:
                    raise ParseError(
                        "Attempt to use symbol from unknown prefix: %s" % symprefix
                    )
                # it's a float .. let it through for now
                sym = "%s.%s" % (symprefix, sym)
                symprefix = self.prefix
        else:
            symprefix = self.prefix
        return "%s.%s" % (symprefix, sym)

    def add_import(self, name, grammar_hash):
        LOG.debug(
            "%s: adding import %s -> %s to %r",
            self.prefix,
            name,
            grammar_hash,
            self.imports,
        )
        if name in self.imports:
            raise ParseError("redefined import %s" % name)
        self.imports[name] = (grammar_hash, self.line_no)

    def sanity_check(self):
        unused = set(self.imports) - self.imports_used
        if unused:
            raise IntegrityError(
                "Unused import%s: %s" % ("s" if len(unused) > 1 else "", list(unused))
            )


class Grammar(object):
    """Generate a language conforming to a given grammar specification.

    A Grammar consists of a set of symbol definitions which are used to define the
    structure of a language. The Grammar object is created from a text input with the
    format described below, and then used to generate randomly constructed instances of
    the described language. The entrypoint of the grammar is the named symbol 'root'.
    Comments are allowed anywhere in the file, preceded by a hash character (``#``).

    Symbols can either be named or implicit. A named symbol consists of a symbol name at
    the beginning of a line, followed by at least one whitespace character, followed by
    the symbol definition.

    ::

        SymbolName  Definition

    Implicit symbols are defined without being assigned an explicit name. For example a
    regular expression can be used in a concatenation definition directly, without being
    assigned a name. Choice symbols cannot be defined implicitly.

    ::

        ModuleName  import("filename")

    Imports allow you to break up grammars into multiple files. A grammar which imports
    another assigns it a local name ``ModuleName``, which may be used to access symbols
    from that grammar such as ``ModuleName.Symbol``, etc. Everything should work as
    expected, including references. Modules must be imported before they can be used.
    """

    _RE_LINE = re.compile(
        r"""^((?P<broken>.*)\\
            |\s*(?P<comment>\#).*
            |(?P<nothing>\s*)
            |(?P<name>[\w:-]+)
             (?P<type>(?P<weight>\s+(\d*\.)?\d+(e-?\d+)?\s+)
              |\s*\+\s*
              |\s+import\(\s*
              |\s+)
             (?P<def>[^\s].*)
            |\s+(\+|(?P<contweight>(\d*\.)?\d+(e-?\d+)?))\s*(?P<cont>.+))$
        """,
        re.VERBOSE,
    )

    def __init__(self, grammar, limit=DEFAULT_LIMIT, **kwargs):
        self._limit = limit
        self.symtab = {}
        self.tracked = set()
        self.funcs = kwargs
        self.recursive_syms = set()
        if "rndint" not in self.funcs:
            self.funcs["rndint"] = lambda a, b: str(random.randint(int(a), int(b)))
        if "rndpow2" not in self.funcs:
            self.funcs["rndpow2"] = lambda a, b: str(
                max(2 ** random.randint(0, int(a)) + random.randint(-int(b), int(b)), 0)
            )
        if "rndflt" not in self.funcs:
            self.funcs["rndflt"] = lambda a, b: str(random.uniform(float(a), float(b)))
        if "eval" not in self.funcs:
            self.funcs["eval"] = None  # eval is a special case in FuncSymbol.generate
        if "push" not in self.funcs:
            self.funcs["push"] = None  # push is a special case in FuncSymbol.generate
        if "pop" not in self.funcs:
            self.funcs["pop"] = None  # pop is a special case in FuncSymbol.generate
        if "id" not in self.funcs:
            self.funcs["id"] = None  # id is a special case in FuncSymbol.generate
        if "import" in self.funcs:
            raise IntegrityError("'import' is a reserved function name")

        if hasattr(grammar, "read"):
            grammar = _file_to_unicode(grammar)
        elif isinstance(grammar, bytes):
            grammar = io.StringIO(grammar.decode("utf-8"))
        else:
            grammar = io.StringIO(grammar)

        # Initial definitions use hash of the grammar as the prefix, keeping track of
        # the first used friendly name ("" for top level). When grammar and imports are
        # fully parsed, do a final pass to rename hash prefixes to friendly prefixes.

        imports = {}  # hash -> friendly prefix
        self.parse(grammar, imports)
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
        LOG.debug("parsing new grammar %r:%s (%s)", grammar_fn, grammar_hash, prefix)
        imports[grammar_hash] = prefix
        grammar.seek(0)
        pstate = _ParseState(grammar_hash, self, grammar_fn)

        try:
            sym = None
            ljoin = ""
            for line in grammar:
                pstate.line_no += 1
                pstate.n_implicit = -1
                LOG.debug("parsing line # %d: %s", pstate.line_no, line.rstrip())
                # allow commented out lines anywhere, even between broken lines
                if line.lstrip().startswith("#"):
                    continue
                match = Grammar._RE_LINE.match("%s%s" % (ljoin, line))
                if match is None:
                    raise ParseError(
                        "Failed to parse definition at: %s%s" % (ljoin, line.rstrip())
                    )
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
                        weight = (
                            float(match.group("weight"))
                            if match.group("weight")
                            else "+"
                        )
                        sym = ChoiceSymbol(sym_name, pstate)
                        sym.append(_Symbol.parse(sym_def, pstate), weight, pstate)
                    elif sym_type.startswith("import("):
                        # import
                        if "%s.%s" % (grammar_hash, sym_name) in self.symtab:
                            raise ParseError(
                                "Redefinition of symbol %s previously declared on line %d"
                                % (
                                    sym_name,
                                    self.symtab[
                                        "%s.%s" % (grammar_hash, sym_name)
                                    ].line_no,
                                )
                            )
                        sym, defn = TextSymbol.parse(sym_def, pstate, no_add=True)
                        defn = defn.strip()
                        if not defn.startswith(")"):
                            raise ParseError(
                                "Expected ')' parsing import at: %s" % defn
                            )
                        defn = defn[1:].lstrip()
                        if defn.startswith("#") or defn:
                            raise ParseError(
                                "Unexpected input following import: %s" % defn
                            )
                        # resolve sym.value from current grammar path or "."
                        import_paths = [sym.value]
                        if grammar_fn is not None:
                            import_paths.insert(
                                0, os.path.join(os.path.dirname(grammar_fn), sym.value)
                            )
                        for import_fn in import_paths:
                            try:
                                with io.open(import_fn, encoding="utf-8") as import_fd:
                                    import_prefix = (
                                        "%s.%s" % (prefix, sym_name)
                                        if prefix
                                        else sym_name
                                    )
                                    import_hash = self.parse(
                                        _file_to_unicode(import_fd),
                                        imports,
                                        prefix=import_prefix,
                                    )
                                    pstate.add_import(sym_name, import_hash)
                                break
                            except IOError:
                                pass
                        else:
                            raise IntegrityError(
                                "Could not find imported grammar: %s" % sym.value
                            )
                    else:
                        # sym def
                        sym = ConcatSymbol.parse(sym_name, sym_def, pstate)
                else:
                    # continuation of choice
                    if sym is None or not isinstance(sym, ChoiceSymbol):
                        raise ParseError("Unexpected continuation of choice symbol")
                    weight = (
                        float(match.group("contweight"))
                        if match.group("contweight")
                        else "+"
                    )
                    sym.append(
                        _Symbol.parse(match.group("cont"), pstate), weight, pstate
                    )

            pstate.sanity_check()
        except (IntegrityError, ParseError):
            raise
        except Exception as err:
            raise ParseError("%s: %s" % (type(err).__name__, str(err)))
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
                raise ParseError(
                    "Failed to reassign %s to proper namespace after parsing" % symname
                )
            newname = "".join((newprefix, "." if newprefix else "", name))
            if symname != newname:
                LOG.debug("reprefixed %s -> %s", symname, newname)
            return "".join(("@" if ref else "", newname))

        # rename prefixes to friendly names
        for oldname in list(self.symtab):
            sym = self.symtab[oldname]
            assert oldname == sym.name
            newname = get_prefixed(oldname)
            if oldname != newname:
                sym.name = newname
                if newname in self.symtab:
                    raise ParseError("symbol %s would be overwritten" % newname)
                self.symtab[newname] = sym
                del self.symtab[oldname]
            sym.map(get_prefixed)
            if isinstance(sym, FuncSymbol) and sym.fname == "eval":
                prefix = sym.imports.prefix
                sym.imports = {
                    prefix: imports[hash_]
                    for (prefix, (hash_, _)) in sym.imports.imports.items()
                }
                sym.imports[""] = imports[prefix]
                LOG.debug(
                    "preserving imports for eval in %s: %r", sym.name, sym.imports
                )
        self.tracked = {get_prefixed(t) for t in self.tracked}

    def normalize(self):
        # normalize symbol tree (remove implicit concats, etc.)
        for name in list(self.symtab):
            try:
                sym = self.symtab[name]
            except KeyError:
                continue  # can happen if symbol is optimized out
            sym.normalize(self)

    def sanity_check(self):
        LOG.debug("sanity checking symtab: %s", self.symtab)
        LOG.debug("tracked symbols: %s", self.tracked)
        funcs_used = {"rndflt", "rndint", "rndpow2", "eval", "id", "push", "pop"}
        for sym in self.symtab.values():
            sym.sanity_check(self)
            if isinstance(sym, FuncSymbol):
                funcs_used.add(sym.fname)
        if set(self.funcs) != funcs_used:
            unused_kwds = tuple(set(self.funcs) - funcs_used)
            raise IntegrityError(
                "Unused keyword argument%s: %s"
                % ("s" if len(unused_kwds) > 1 else "", unused_kwds)
            )
        if "root" not in self.symtab:
            raise IntegrityError("Missing required start symbol: root")
        syms_used = {"root"}
        to_check = {"root"}
        checked = set()
        while to_check:
            sym = self.symtab[to_check.pop()]
            checked.add(sym.name)
            children = sym.children()
            LOG.debug(
                "%s is %s with %d children %s",
                sym.name,
                type(sym).__name__,
                len(children),
                list(children),
            )
            syms_used |= children
            to_check |= children - checked
        # ignore unused symbols that came from an import, Text, Regex, or Bin
        syms_ignored = {s for s in self.symtab if re.search(r"[.\[]", s)}
        unused_syms = list(set(self.symtab) - syms_used - syms_ignored)
        if unused_syms:
            raise IntegrityError(
                "Unused symbol%s: %s"
                % ("s" if len(unused_syms) > 1 else "", unused_syms)
            )

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
                    if any(
                        child in terminators or maybes[child]
                        for child in self.symtab[sym].children()
                    ):
                        maybes[sym] = True
                        do_over = True
        nons = [sym for sym in maybes if not maybes[sym]]
        if nons:
            raise IntegrityError(
                "Symbol has no paths to termination (infinite recursion?): %s"
                % nons[0],
                self.symtab[nons[0]].line_no,
            )

        children = {}
        for sym in self.symtab.values():
            # capture children of non-implicit symbols (which includes recursing
            # into implicit symbols)
            if "[" not in sym.name:
                children[sym.name] = set()
                togo = sym.children()
                while togo:
                    child = togo.pop()
                    if "[" in child:  # implicit symbol, keep going
                        togo |= self.symtab[child].children()
                        togo -= children[sym.name]
                    else:
                        children[sym.name].add(child)

        # check for recursion
        for sym_name, sym_children in children.items():
            if sym_name in sym_children:
                self.recursive_syms.add(sym_name)
                LOG.debug("%s is directly recursive", sym_name)
                continue
            # `issue` is a map of descendents (of any degree) to shortest ancestry
            # from this sym_name
            issue = {child_name: [] for child_name in sym_children}
            done = set()
            while issue:
                child_name = list(issue.keys())[0]
                child_backtrace = issue.pop(child_name) + [child_name]
                done.add(child_name)
                for grandchild_name in children[child_name]:
                    if grandchild_name in done | set(issue):
                        continue
                    if grandchild_name == sym_name:
                        self.recursive_syms.add(sym_name)
                        LOG.debug(
                            "%s is recursive through %r (%d degree)",
                            sym_name,
                            child_backtrace,
                            len(child_backtrace),
                        )
                        issue = None
                        break
                    issue[grandchild_name] = child_backtrace

    def is_limit_exceeded(self, gstate):
        return (self._limit is not None and gstate.length >= self._limit) or any(
            sym["limited"] for sym in gstate.recursive_syms.values()
        )

    def generate(self, start="root"):
        if not isinstance(start, _GenState):
            gstate = _GenState(self)
            gstate.symstack = [start]
            gstate.instances = {sym: [] for sym in self.tracked}
            gstate.instance_backlog = {sym: [] for sym in self.tracked}
        else:
            gstate = start
        tracking = []
        while gstate.symstack:
            this = gstate.symstack.pop()
            backlog = False
            if isinstance(this, tuple):
                cmd = this[0]
                if cmd == "unwind":
                    if this[1] in gstate.recursive_syms:
                        recursion_state = gstate.recursive_syms[this[1]]
                        recursion_state["depth"] -= 1
                        if recursion_state["depth"] <= 0:
                            del gstate.recursive_syms[this[1]]
                    continue
                elif cmd == "resetbackref":
                    gstate.backrefs.pop()
                    continue
                elif cmd == "backlog":
                    this = this[1]
                    backlog = True
                elif cmd == "untrack":
                    tracked = tracking.pop()
                    assert (
                        this[1] == tracked[0]
                    ), "Tracking mismatch: expected '%s', got '%s'" % (
                        tracked[0],
                        this[1],
                    )
                    instance = "".join(gstate.output[tracked[1] :])
                    if "[concat" in this[1]:
                        gstate.backrefs[-1][this[1]] = instance
                    elif this[2]:
                        gstate.instance_backlog[this[1]].append(instance)
                    else:
                        gstate.instances[this[1]].append(instance)
                    continue
                elif cmd == "choice":
                    sym, choice = this[1:]
                    gstate.choice_stack.setdefault(sym, []).append(choice)
                    # not sure if this is true ... only one way to find out
                    # if it is true, choice_stack can be a simple lut
                    # ie. not a stack at all
                    assert len(gstate.choice_stack[sym]) == 1
                    continue
                else:
                    raise GenerationError("Unknown tuple command: %s" % cmd)
            if this in self.recursive_syms:
                if this in gstate.recursive_syms:
                    recursive_state = gstate.recursive_syms[this]
                    recursive_state["depth"] += 1
                    if recursive_state["depth"] >= recursive_state["depth_limit"]:
                        recursive_state["limited"] = True
                else:
                    gstate.recursive_syms[this] = {
                        "depth": 1,
                        "depth_limit": random.randint(2, random.randint(2, 25)),
                        "limited": False,
                    }
            # need to capture everything generated by this symbol and add to "instances"
            if this in self.tracked:
                if not backlog and gstate.instance_backlog[this]:
                    # instance previously generated in the backlog, use it instead
                    idx = random.randrange(len(gstate.instance_backlog[this]))
                    value = gstate.instance_backlog[this].pop(idx)
                    gstate.instances[this].append(value)
                    gstate.append(value)
                    continue
                gstate.symstack.append(("untrack", this, backlog))
                tracking.append((this, len(gstate.output)))
            gstate.symstack.append(("unwind", this))
            if "[" not in this:
                gstate.symstack.append(("resetbackref",))
                gstate.backrefs.append({})
            try:
                self.symtab[this].generate(gstate)
            except GenerationError:
                raise
            except Exception as err:
                raise GenerationError("%s: %s" % (type(err).__name__, str(err)))
        try:
            return "".join(gstate.output)
        except TypeError:
            return b"".join(gstate.output)


class _Symbol(object):
    _RE_DEFN = re.compile(
        r"""^((?P<quote>["'])
             |(?P<hexstr>x["'])
             |(?P<regex>/)
             |(?P<implconcat>\()
             |(?P<infunc>[,)])
             |(?P<implchoice>\|)
             |(?P<comment>\#).*
             |(?P<func>\w+)\(
             |(?P<maybe>\?)
             |(?P<repeat>[{<]\s*(?P<a>\d+|\*)\s*(,\s*(?P<b>\d+|\*)\s*)?[}>])
             |@(?P<refprefix>[\w-]+\.)?(?P<ref>[\w:-]+)
             |(?P<symprefix>[\w-]+\.)?(?P<sym>[\w:-]+)
             |(?P<ws>\s+))""",
        re.VERBOSE,
    )

    def __init__(self, name, pstate, no_add=False):
        if name == "%s.import" % pstate.prefix:
            raise ParseError("'import' is a reserved name")
        unprefixed = name.split(".", 1)[1]
        if unprefixed in pstate.imports:
            raise ParseError(
                "Redefinition of symbol %s previously declared on line %d"
                % (unprefixed, pstate.imports[unprefixed][1])
            )
        self.name = name
        self.line_no = pstate.line_no
        LOG.debug("\t%s %s", type(self).__name__.lower()[:-6], name)
        if not no_add:
            if name in pstate.grmr.symtab and not isinstance(
                pstate.grmr.symtab[name], (_AbstractSymbol, RefSymbol)
            ):
                unprefixed = name.split(".", 1)[1]
                raise ParseError(
                    "Redefinition of symbol %s previously declared on line %d"
                    % (unprefixed, pstate.grmr.symtab[name].line_no)
                )
            pstate.grmr.symtab[name] = self
        self.can_terminate = None

    def map(self, fcn):
        pass

    def normalize(self, grmr):
        pass

    def sanity_check(self, grmr):
        pass

    def generate(self, gstate):
        raise GenerationError(
            "Can't generate symbol %s of type %s" % (self.name, type(self))
        )

    def children(self):
        return set()

    def update_can_terminate(self, grmr):
        if all(grmr.symtab[c].can_terminate for c in self.children()):
            LOG.debug("%s can terminate", self.name)
            self.can_terminate = True
            return True
        return False

    @staticmethod
    def _parse(defn, pstate, in_func, in_concat):
        result = []
        while defn:
            match = _Symbol._RE_DEFN.match(defn)
            if match is None:
                raise ParseError("Failed to parse definition at: %s" % defn)
            LOG.debug(
                "parsed %s from %s",
                {k: v for k, v in match.groupdict().items() if v is not None},
                defn,
            )
            if match.group("ws") is not None:
                defn = defn[match.end(0) :]
                continue
            if match.group("quote"):
                sym, defn = TextSymbol.parse(defn, pstate)
            elif match.group("hexstr"):
                sym, defn = BinSymbol.parse(defn, pstate)
            elif match.group("regex"):
                sym, defn = RegexSymbol.parse(defn, pstate)
            elif match.group("func"):
                defn = defn[match.end(0) :]
                sym, defn = FuncSymbol.parse(match.group("func"), defn, pstate)
            elif match.group("ref"):
                ref = pstate.get_prefixed(match.group("refprefix"), match.group("ref"))
                try:
                    backref = int(match.group("ref"))
                except ValueError:
                    pass
                else:
                    if match.group("refprefix"):
                        raise ParseError("Invalid reference syntax at: %s" % defn)
                    if (
                        not (1 <= backref <= len(pstate.capture_groups))
                        or pstate.capture_groups[backref - 1] is None
                    ):
                        raise IntegrityError("Invalid backreference at: %s" % defn)
                    ref = pstate.capture_groups[backref - 1]
                sym = RefSymbol(ref, pstate)
                defn = defn[match.end(0) :]
            elif match.group("sym"):
                sym_name = pstate.get_prefixed(
                    match.group("symprefix"), match.group("sym")
                )
                try:
                    sym = pstate.grmr.symtab[sym_name]
                except KeyError:
                    sym = _AbstractSymbol(sym_name, pstate)
                defn = defn[match.end(0) :]
            elif match.group("comment"):
                defn = ""
                break
            elif match.group("infunc"):
                if in_func or (in_concat and match.group("infunc") == ")"):
                    break
                raise ParseError("Unexpected token in definition: %s" % defn)
            elif match.group("implconcat"):
                capture = len(pstate.capture_groups)
                pstate.capture_groups.append(None)
                parts, defn = _Symbol._parse(defn[match.end(0) :], pstate, False, True)
                if defn[0] not in ")|":
                    raise ParseError("Expecting ) at: %s" % defn)
                if defn[0] == "|":
                    # implicit choice:
                    name = "[choice (line %d #%d)]" % (
                        pstate.line_no,
                        pstate.implicit(),
                    )
                    sym = ChoiceSymbol(name, pstate)
                    sym.append(parts, 1, pstate)
                    while defn[0] == "|":
                        parts, defn = _Symbol._parse(defn[1:], pstate, False, True)
                        if not defn[0] in ")|":
                            raise ParseError("Expecting ) or | at: %s" % defn)
                        sym.append(parts, 1, pstate)
                else:
                    name = "[concat (line %d #%d)]" % (
                        pstate.line_no,
                        pstate.implicit(),
                    )
                    sym = ConcatSymbol(name, pstate)
                    sym.extend(parts)
                pstate.capture_groups[capture] = sym.name
                defn = defn[1:]
            elif match.group("implchoice"):
                if in_concat:
                    break
                raise ParseError("Unexpected token in definition: %s" % defn)
            elif match.group("maybe") or match.group("repeat"):
                if not result:
                    raise ParseError("Unexpected token in definition: %s" % defn)
                if match.group("maybe"):
                    repeat = RepeatSymbol
                    min_, max_ = 0, 1
                else:
                    if {"{": "}", "<": ">"}[match.group(0)[0]] != match.group(0)[-1]:
                        raise ParseError("Repeat symbol mismatch at: %s" % defn)
                    repeat = {"{": RepeatSymbol, "<": RepeatSampleSymbol}[
                        match.group(0)[0]
                    ]
                    min_ = "*" if match.group("a") == "*" else int(match.group("a"))
                    max_ = (
                        ("*" if match.group("b") == "*" else int(match.group("b")))
                        if match.group("b")
                        else min_
                    )
                parts = result.pop()
                name = "[repeat (line %d #%d)]" % (pstate.line_no, pstate.implicit())
                sym = repeat(name, min_, max_, pstate)
                sym.append(parts)
                defn = defn[match.end(0) :]
            result.append(sym.name)
        return result, defn

    @staticmethod
    def parse_func_arg(defn, pstate):
        return _Symbol._parse(defn, pstate, True, False)

    @staticmethod
    def parse(defn, pstate):
        res, remain = _Symbol._parse(defn, pstate, False, False)
        if remain:
            raise ParseError("Unexpected token in definition: %s" % remain)
        return res


class _AbstractSymbol(_Symbol):
    def __init__(self, name, pstate):
        _Symbol.__init__(self, name, pstate)

    def sanity_check(self, grmr):
        raise IntegrityError("Symbol %s used but not defined" % self.name)


class BinSymbol(_Symbol):
    """Binary data

    ::

        SymbolName      x'41414141'

    Defines a chunk of binary data encoded in hex notation. ``BinSymbol`` and
    ``TextSymbol`` cannot be combined in the output.
    """

    _RE_QUOTE = re.compile(r"""(?P<end>["'])""")

    def __init__(self, value, pstate):
        name = "%s.[bin (line %d #%d)]" % (
            pstate.prefix,
            pstate.line_no,
            pstate.implicit(),
        )
        _Symbol.__init__(self, name, pstate)
        try:
            self.value = binascii.unhexlify(value.encode("ascii"))
        except (UnicodeEncodeError, TypeError) as err:
            raise ParseError("Invalid hex string: %s" % err)
        self.can_terminate = True

    def generate(self, gstate):
        gstate.append(self.value)

    @staticmethod
    def parse(defn, pstate):
        start, qchar, defn = defn[0], defn[1], defn[2:]
        if start != "x":
            raise ParseError(
                "Error parsing binary string at: %s%s%s" % (start, qchar, defn)
            )
        if qchar not in "'\"":
            raise ParseError("Error parsing binary string at: %s%s" % (qchar, defn))
        enquo = defn.find(qchar)
        if enquo == -1:
            raise ParseError("Unterminated bin literal!")
        value, defn = defn[:enquo], defn[enquo + 1 :]
        sym = BinSymbol(value, pstate)
        return sym, defn


class ChoiceSymbol(_Symbol):
    """Choose between several options

    ::

        SymbolName      Weight1     SubSymbol1
                       [Weight2     SubSymbol2]
                       [Weight3     SubSymbol3]

    A choice consists of one or more weighted sub-symbols. At generation, only one of
    the sub-symbols will be generated at random, with each sub-symbol being generated
    with probability of weight/sum(weights) (the sum of all weights in this choice).
    Weight is a decimal number in the range 0.0 to 1.0 inclusive.

    Weight can also be ``+``, which imports another ``ChoiceSymbol`` into this
    definition. SubSymbol must be another ``ChoiceSymbol`` (or a concatenation of one
    or more ``TextSymbol``s and exactly one ``ChoiceSymbol``).
    """

    def __init__(self, name, pstate=None):
        name = "%s.%s" % (pstate.prefix, name)
        _Symbol.__init__(self, name, pstate)
        self.total = 0.0
        self.values = []
        self.weights = []
        self.was_plus = []
        self._choices_terminate = []
        self.normalized = False
        self.length = None

    def append(self, value, weight, pstate):
        if weight != "+":
            if not 0.0 <= weight <= 1.0:
                raise IntegrityError(
                    "Invalid weight value for choice: %.2f (expecting [0,1])" % weight
                )
            self.total += weight
        name = "[concat (line %d #%d)]" % (pstate.line_no, pstate.implicit())
        sym = ConcatSymbol(name, pstate)
        sym.extend(value)
        self.values.append(sym.name)
        self.weights.append(weight)
        self.was_plus.append(None)
        self._choices_terminate.append(None)

    def _cache_choice(self, choice, gstate):
        gstate.choice_stack.setdefault(self.name, []).append(choice)

    def _internal_choice(self, total, used, plus_state, result, gstate):
        target = random.uniform(0, total[0])
        LOG.debug(
            "%s: looking for target %.2f from total %.2f", self.name, target, total[0]
        )
        LOG.debug("-> blacklist: %r", used)
        for i, (weight, value, was_plus) in enumerate(
            zip(self.weights, self.values, self.was_plus)
        ):
            if was_plus and plus_state is not None:
                choice = gstate.grmr.symtab[gstate.grmr.symtab[value].choice]
                if isinstance(used[i], bool):
                    plus_state[i] = {"total": [choice.total], "substate": {}}
                    used[i] = [False] * len(choice.values)
                target -= plus_state[i]["total"][0]
                if target < 0.0:
                    LOG.debug("choice is in + at %d", i)
                    total[0] -= plus_state[i]["total"][0]
                    choice._internal_choice(
                        plus_state[i]["total"],
                        used[i],
                        plus_state[i]["substate"],
                        result,
                        gstate,
                    )
                    total[0] += plus_state[i]["total"][0]
                    result.append((self.name, value))
                    return
                LOG.debug(
                    "-> %d had weight of %.2f, not the target",
                    i,
                    plus_state[i]["total"][0],
                )
            elif not used[i]:
                target -= weight
                if target < 0.0:
                    LOG.debug("choice is at %d", i)
                    used[i] = True
                    total[0] -= weight
                    result.append((self.name, value))
                    return
                LOG.debug("-> %d had weight of %.2f, not the target", i, weight)
        raise GenerationError(
            "Too much total weight in %s? remainder is %.2f from %.2f total"
            % (self.name, target, total[0])
        )

    def choice(self, whitelist, gstate):
        if gstate.choice_stack.get(self.name):
            return gstate.choice_stack[self.name].pop()
        if whitelist is not None:
            assert len(whitelist) == len(self.values)
            blacklist = [not x for x in whitelist]
            total = self.total - sum(
                weight for (weight, used) in zip(self.weights, blacklist) if used
            )
        else:
            blacklist = [False] * len(self.values)
            total = self.total
        result = []
        self._internal_choice([total], blacklist, None, result, gstate)
        assert len(result) == 1
        assert result[0][0] == self.name
        return result[0][1]

    def sample(self, k, gstate):
        # should return cache results for future generate()s
        used, total, plus_state, result = (
            ([False] * len(self.values)),
            [self.total],
            {},
            [],
        )
        while len(result) < k:
            this_result = []
            if total[0] <= 0.0:
                break
            self._internal_choice(total, used, plus_state, this_result, gstate)
            result.append(
                tuple(("choice", choice[0], choice[1]) for choice in this_result)
            )
        return result

    def normalize(self, grmr):
        if self.normalized:
            return
        self.normalized = True
        self.length = len(self.values)
        for i, (value, weight) in enumerate(zip(self.values, self.weights)):
            if weight == "+":
                grmr.symtab[value].normalize(grmr)
                if not grmr.symtab[value].choice:
                    raise IntegrityError(
                        "Expecting exactly one ChoiceSymbol in %s" % self.name
                    )
                choice = grmr.symtab[grmr.symtab[value].choice]
                if any(weight == "+" for weight in choice.weights):
                    if choice.normalized:
                        # recursive definition
                        raise IntegrityError(
                            "Can't resolve weight for '+' in %s, expansion of '%s' "
                            "causes unbounded recursion" % (self.name, choice.name),
                            self.line_no + i,
                        )
                choice.normalize(grmr)  # resolve the child '+' first
                self.weights[i] = choice.total
                self.total += self.weights[i]
                self.was_plus[i] = True
                self.length += choice.length - 1  # -1 for the entry in self.values
        if self.total <= 0.0:
            raise IntegrityError(
                "Invalid total weight for symbol %s: %r" % (self.name, self.total)
            )

    def generate(self, gstate):
        if gstate.grmr.is_limit_exceeded(gstate) and self.can_terminate:
            gstate.symstack.append(self.choice(self._choices_terminate, gstate))
        else:
            gstate.symstack.append(self.choice(None, gstate))

    def children(self):
        return set(self.values)

    def map(self, fcn):
        self.values = [fcn(j) for j in self.values]

    def update_can_terminate(self, grmr):
        for i, choice in enumerate(self.values):
            if grmr.symtab[choice].can_terminate:
                self._choices_terminate[i] = True
        if any(self._choices_terminate):
            LOG.debug("%s can terminate", self.name)
            self.can_terminate = True
            return True
        return False

    def __len__(self):
        return self.length

    def __repr__(self):
        return "ChoiceSymbol(%s)" % list(zip(self.values, self.weights))


class ConcatSymbol(_Symbol, list):
    """Concatenation of subsymbols

    ::

        SymbolName      SubSymbol1 [SubSymbol2] ...

    A concatenation consists of one or more symbols which will be generated in
    succession. The sub-symbol can be any named symbol, reference, or an implicit
    declaration of terminal symbol types. A concatenation can also be implicitly used
    as the sub-symbol of a ``ChoiceSymbol``, or inline using ``(`` and ``)``.
    eg::

        SymbolName      SubSymbol1 ( SubSymbol2 SubSymbol3 ) ...

    This is most useful for defining implicit repeats for some terms in the
    concatenation.
    """

    def __init__(self, name, pstate, no_prefix=False):
        name = "%s.%s" % (pstate.prefix, name) if not no_prefix else name
        _Symbol.__init__(self, name, pstate)
        list.__init__(self)
        # if this concat is choosable, this will be the sym.name of the subchoice
        self.choice = None
        self.normalized = None

    def children(self):
        return set(self)

    def map(self, fcn):
        list.__init__(self, [fcn(i) for i in self])

    def generate(self, gstate):
        gstate.symstack.extend(reversed(self))

    def normalize(self, grmr):
        if self.normalized:
            return
        if self.normalized is False:
            raise IntegrityError("Symbol has no paths to termination")
        self.normalized = False
        choice = None
        for child in self:
            this_choice = None
            if isinstance(grmr.symtab[child], ChoiceSymbol):
                this_choice = child
            elif isinstance(grmr.symtab[child], ConcatSymbol):
                grmr.symtab[child].normalize(grmr)
                if grmr.symtab[child].choice is not None:
                    this_choice = grmr.symtab[child].choice
            if this_choice is not None:
                if choice is not None:
                    choice = None
                    break  # two choices, not choosable
                choice = this_choice
        if choice is not None:
            self.choice = choice
        self.normalized = True

    @staticmethod
    def parse(name, defn, pstate):
        result = ConcatSymbol(name, pstate)
        result.extend(_Symbol.parse(defn, pstate))
        return result


class FuncSymbol(_Symbol):
    """Function

    ::

        SymbolName      function(SymbolArg1[,...])

    This denotes an externally defined function. The function name can be any valid
    Python identifier. It can accept an arbitrary number of arguments, but must return
    a single string which is the generated value for this symbol instance. Functions
    must be passed as keyword arguments into the Grammar object constructor.

    The following functions are built-in::

        push(expr)       Evaluate an expression, but don't output it. Can be pop()'ed
                         later when required.
                         Use for out-of-order generation.
        pop()            Output an expression previously generated in push().
        eval(sym)        Evaluating a grammar string to a grammar symbol, and generates
                         that symbol.
        rndflt(a,b)      A random floating-point decimal number between ``a`` and ``b``
                         inclusive.
        rndint(a,b)      A random integer between ``a`` and ``b`` inclusive.
        rndpow2(exponent_limit, variation)
                         This function is intended to return edge values around powers
                         of 2. It is equivalent to:
                         ``pow(2, rndint(0, exponent_limit))
                           + rndint(-variation, variation)``
    """

    def __init__(self, name, pstate):
        sname = "%s.[%s (line %d #%d)]" % (
            pstate.prefix,
            name,
            pstate.line_no,
            pstate.implicit(),
        )
        _Symbol.__init__(self, sname, pstate)
        self.fname = name
        self.args = []
        self.imports = None
        if name == "eval":
            self.imports = pstate  # retain pstate for resolving imports later

    def sanity_check(self, grmr):
        if self.fname not in grmr.funcs:
            raise IntegrityError("Function %s used but not defined" % self.fname)

    def generate(self, gstate):
        args = []
        for arg in self.args:
            if isinstance(arg, numbers.Number):
                args.append(arg)
            else:
                symstack, output = gstate.symstack, gstate.output
                gstate.symstack, gstate.output = [arg], []
                args.append(gstate.grmr.generate(gstate))
                gstate.symstack, gstate.output = symstack, output
        if self.fname == "eval" and gstate.grmr.funcs["eval"] is None:
            # TODO: this should support imports in the original grammar
            if len(args) != 1:
                raise TypeError(
                    "eval() takes exactly 1 arguments (%d given)" % len(args)
                )
            try:
                prefix, name = args[0].rsplit(".", 1)
            except ValueError:
                prefix, name = "", args[0]
            prefix = self.imports[prefix]
            if prefix:
                gstate.symstack.append("%s.%s" % (prefix, name))
            else:
                gstate.symstack.append(name)
        elif self.fname == "id" and gstate.grmr.funcs["id"] is None:
            if len(args) != 0:
                raise TypeError("id() takes 0 arguments (%d given)" % len(args))
            gstate.generate_id()
        elif self.fname == "push" and gstate.grmr.funcs["push"] is None:
            if len(args) != 1:
                raise TypeError(
                    "push() takes exactly 1 arguments (%d given)" % len(args)
                )
            gstate.push_stack.append(args[0])
        elif self.fname == "pop" and gstate.grmr.funcs["pop"] is None:
            if len(args) != 0:
                raise TypeError(
                    "pop() takes exactly 0 arguments (%d given)" % len(args)
                )
            gstate.append(gstate.push_stack.pop())
        else:
            gstate.append(gstate.grmr.funcs[self.fname](*args))

    def children(self):
        return set(a for a in self.args if not isinstance(a, numbers.Number))

    def map(self, fcn):
        _fcn = lambda x: x if isinstance(x, numbers.Number) else fcn(x)
        self.args = [_fcn(i) for i in self.args]

    @staticmethod
    def parse(name, defn, pstate):
        if name == "import":
            raise ParseError("'import' is a reserved function name")
        result = FuncSymbol(name, pstate)
        done = False
        while not done:
            arg, defn = _Symbol.parse_func_arg(defn, pstate)
            if defn[0] not in ",)":
                raise ParseError("Expected , or ) parsing function args at: %s" % defn)
            done = defn[0] == ")"
            defn = defn[1:]
            if arg or not done:
                numeric_arg = False
                if len(arg) == 1 and isinstance(
                    pstate.grmr.symtab[arg[0]], _AbstractSymbol
                ):
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
                    sym = ConcatSymbol(
                        "%s.%s]" % (result.name[:-1], len(result.args)),
                        pstate,
                        no_prefix=True,
                    )
                    sym.extend(arg)
                    result.args.append(sym.name)
        return result, defn


class RefSymbol(_Symbol):
    """Reference an instance of another symbol

    ::

        SymbolRef       @SymbolName

    Symbol references allow a generated symbol to be used elsewhere in the grammar.
    Referencing a symbol by ``@Symbol`` will output a generated value of ``Symbol``
    from elsewhere in the output.
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
                gstate.append(backrefs[self.ref])
            except KeyError:
                raise GenerationError("No symbols generated yet for backreference")
        elif gstate.instances[self.ref]:
            gstate.append(random.choice(gstate.instances[self.ref]))
        elif len(gstate.instance_backlog[self.ref]) > 1 and random.random() < 0.3:
            LOG.debug(
                "No instances of %s yet, using one from the backlog instead", self.ref
            )
            gstate.append(random.choice(gstate.instance_backlog[self.ref]))
        else:
            LOG.debug(
                "No instances of %s yet, generating one instead of a reference",
                self.ref,
            )
            gstate.symstack.append(("backlog", self.ref))

    def children(self):
        return {self.ref}

    def map(self, fcn):
        self.ref = fcn(self.ref)


class RegexSymbol(ConcatSymbol):
    """Text generated by a regular expression

    ::

        SymbolName     /id[0-9]{4}/  (generates strings between 'id0000' and 'id9999')
        ...            /a?far/       (generates either 'far' or 'afar')

    A regular expression (regex) symbol is a minimal regular expression implementation
    used for generating text patterns (rather than the traditional use for matching text
    patterns). A regex symbol consists of one or more parts in succession, and each part
    consists of a character set definition optionally followed by a repetition
    specification.

    The character set definition can be a single character, a period ``.`` to denote any
    ASCII character, a set of characters in brackets eg. ``[0-9a-f]``, or an inverted
    set of characters ``[^a-z]`` (any character except a-z). As shown, ranges can be
    defined by using a dash. The dash character can be matched in a set by putting it
    first or last in the set. Escapes work as in TextSymbol using the backslash
    character.

    The optional repetition specification can be a range of integers in curly braces,
    eg. ``{1,10}`` will generate between 1 and 10 repetitions (at random), a single
    integer in curly braces, eg. ``{10}`` will generate exactly 10 repetitions, or a
    question mark (``?``) which is equivalent to ``{0,1}``.

    A notable exclusion from ordinary regular expression implementations is groups using
    ``()`` or ``(a|b)``. This syntax is *not* supported in RegexSymbol. The characters
    "()|" have no special meaning and do not need to be escaped.
    """

    _RE_PARSE = re.compile(
        r"""^((?P<repeat>\{\s*(?P<a>\d+)\s*(,\s*(?P<b>\d+)\s*)?\}|\?)
                                 |(?P<set>\[\^?)
                                 |(?P<esc>\\.)
                                 |(?P<dot>\.)
                                 |(?P<done>/))""",
        re.VERBOSE,
    )
    _RE_SET = re.compile(r"^(\]|-|[\ud800-\udbff][\udc00-\udfff]|\\?.)")

    def __init__(self, pstate):
        name = "%s.[regex (line %d #%d)]" % (
            pstate.prefix,
            pstate.line_no,
            pstate.implicit(),
        )
        ConcatSymbol.__init__(self, name, pstate, no_prefix=True)
        self.can_terminate = True

    def _impl_name(self, n_implicit):
        name = "%s.%d]" % (self.name[:-1], n_implicit[0])
        n_implicit[0] += 1
        return name

    def new_text(self, value, n_implicit, pstate):
        self.append(
            TextSymbol(self._impl_name(n_implicit), value, pstate, no_prefix=True).name
        )

    def add_repeat(self, min_, max_, n_implicit, pstate):
        rep = RepeatSymbol(
            self._impl_name(n_implicit), min_, max_, pstate, no_prefix=True
        )
        rep.append(self.pop())
        self.append(rep.name)

    @staticmethod
    def parse(defn, pstate):
        result = RegexSymbol(pstate)
        n_implicit = [0]
        if defn[0] != "/":
            raise ParseError("Regex definitions must begin with /")
        defn = defn[1:]
        while defn:
            match = RegexSymbol._RE_PARSE.match(defn)
            if match is None:
                result.new_text(defn[0], n_implicit, pstate)
                defn = defn[1:]
            elif match.group("set"):
                lst = _TextChoiceSymbol(
                    result._impl_name(n_implicit), pstate, no_prefix=True
                )
                inverse = len(match.group("set")) == 2
                defn = defn[match.end(0) :]
                alpha = []
                in_range = False
                while defn:
                    match = RegexSymbol._RE_SET.match(defn)
                    if match.group(0) == "]":
                        if in_range:
                            alpha.append(ord("-"))
                        defn = defn[match.end(0) :]
                        break
                    elif match.group(0) == "-":
                        if in_range or not alpha:
                            raise ParseError("Parse error in regex at: %s" % defn)
                        in_range = True
                    else:
                        if match.group(0).startswith("\\"):
                            alpha.append(
                                ord(
                                    TextSymbol.ESCAPES.get(
                                        match.group(0)[1], match.group(0)[1]
                                    )
                                )
                            )
                        elif len(match.group(0)) == 2:
                            # UCS-2 surrogate pair
                            alpha.append(int(repr(match.group(0))[4:-1], 16))
                        else:
                            alpha.append(ord(match.group(0)))
                        if in_range:
                            end = alpha.pop()
                            start = alpha.pop()
                            if start >= end + 1:
                                raise ParseError("Empty range in regex at: %s" % defn)
                            lst.add(start, end)
                            in_range = False
                    defn = defn[match.end(0) :]
                else:
                    raise ParseError("Unterminated set in regex")
                for char in alpha:
                    lst.add(char)
                if inverse:
                    sub = SparseList(lst)
                    lst.clear()
                    lst.add(ord(" "), ord("~"))
                    lst -= sub
                result.append(lst.name)
            elif match.group("done"):
                return result, defn[match.end(0) :]
            elif match.group("dot"):
                try:
                    pstate.grmr.symtab["%s.[regex alpha]" % pstate.prefix]
                except KeyError:
                    sym = _TextChoiceSymbol("[regex alpha]", pstate)
                    sym.add(ord(" "), ord("~"))
                    sym.line_no = 0
                result.append(sym.name)
                defn = defn[match.end(0) :]
            elif match.group("esc"):
                result.new_text(
                    TextSymbol.ESCAPES.get(match.group(0)[1], match.group(0)[1]),
                    n_implicit,
                    pstate,
                )
                defn = defn[match.end(0) :]
            else:  # repeat
                if not len(result) or isinstance(
                    pstate.grmr.symtab[result[-1]], RepeatSymbol
                ):
                    raise ParseError(
                        "Error parsing regex, unexpected repeat at: %s" % defn
                    )
                if match.group("a"):
                    min_ = int(match.group("a"))
                    max_ = int(match.group("b")) if match.group("b") else min_
                else:
                    min_, max_ = 0, 1
                result.add_repeat(min_, max_, n_implicit, pstate)
                defn = defn[match.end(0) :]
        raise ParseError("Unterminated regular expression")


class RepeatSymbol(ConcatSymbol):
    """Repeat subsymbols a random number of times.

    ::

        SymbolName      SubSymbol {Min,Max}
        SymbolName      SubSymbol {n}
        SymbolName      SubSymbol ?

    Defines a repetition of subsymbols. The number of repetitions is at most ``Max``,
    and at minimum ``Min``. The second parameter is optional, in which case exactly
    ``n`` will be generated. ``?`` is shorthand for {0,1}. ``*`` can also be used, which
    evaluates to the number of choices in SubSymbol (must be ``ChoiceSymbol`` or
    concatenation of text with one ``ChoiceSymbol`` to use ``*``).
    """

    def __init__(self, name, min_, max_, pstate, no_prefix=False):
        name = "%s.%s" % (pstate.prefix, name) if not no_prefix else name
        ConcatSymbol.__init__(self, name, pstate, no_prefix=True)
        self.min_, self.max_ = min_, max_

    def normalize(self, grmr):
        if isinstance(self, RepeatSampleSymbol) or self.min_ == "*" or self.max_ == "*":
            ConcatSymbol.normalize(self, grmr)
            if not self.choice:
                raise IntegrityError(
                    "Expecting exactly one ChoiceSymbol in %s" % self.name
                )
            choice = grmr.symtab[self.choice]
            choice.normalize(grmr)
            LOG.debug("repeat %s value for '*' is %d", self.name, len(choice))
            if self.min_ == "*":
                self.min_ = len(choice)
            if self.max_ == "*":
                self.max_ = len(choice)
        if self.min_ > self.max_ or self.min_ < 0:
            raise IntegrityError(
                "Invalid range for repeat in %s: [%d,%d]"
                % (self.name, self.min_, self.max_)
            )

    def generate(self, gstate):
        if gstate.grmr.is_limit_exceeded(gstate):
            if not self.can_terminate:
                return  # chop the output. this isn't great, but not much choice
            reps = self.min_
        else:
            reps = random.randint(
                self.min_, random.randint(self.min_, self.max_)
            )  # roughly betavariate(0.75, 2.25)
        gstate.symstack.extend(reps * tuple(reversed(self)))

    def update_can_terminate(self, grmr):
        if _Symbol.update_can_terminate(self, grmr):
            return True
        if self.min_ == 0:
            self.can_terminate = True
            LOG.debug("%s can terminate", self.name)
            return True
        return False


class RepeatSampleSymbol(RepeatSymbol):
    """
    **Repeat Unique**:

           ::

               SymbolName      <Min,Max>   SubSymbol

       Defines a repetition of a sub-symbol. The number of repetitions is at most
       ``Max``, and at minimum ``Min``. The sub-symbol must be choosable, ie. a single
       ``ChoiceSymbol`` or concatenation with exactly one ``ChoiceSymbol``.
       The generated repetitions will be unique from the choices in the sub-symbol.
       ``*`` can also be used, which evaluates to the number of choices in the
       sub-symbol (must be ``ChoiceSymbol`` or concatenation of text with one
       ``ChoiceSymbol``).
    """

    def __init__(self, name, min_, max_, pstate, no_prefix=False):
        RepeatSymbol.__init__(self, name, min_, max_, pstate, no_prefix)
        self.in_concat = False
        self.sample_idx = None

    def generate(self, gstate):
        if gstate.grmr.is_limit_exceeded(gstate):
            if not self.can_terminate:
                return  # chop the output. this isn't great, but not much choice
            reps = self.min_
        else:
            reps = random.randint(
                self.min_, random.randint(self.min_, self.max_)
            )  # roughly betavariate(0.75, 2.25)
        # sample the choice (which gives cache values for the symstack), then generate
        # self that many times
        assert self.choice is not None
        for choices in reversed(gstate.grmr.symtab[self.choice].sample(reps, gstate)):
            gstate.symstack.extend(reversed(self))
            gstate.symstack.extend(choices)


class TextSymbol(_Symbol):
    """Text string

    ::

        SymbolName      'some text'
        SymbolName      "some text"

    A text symbol is a string generated verbatim in the output.
    C escape codes are recognized:
        * ``\\0``  null (ASCII 0x00)
        * ``\\a``  bell (ASCII 0x07)
        * ``\\b``  backspace (ASCII 0x08)
        * ``\\t``  horizontal tab (ASCII 0x09)
        * ``\\n``  line feed (ASCII 0x0A)
        * ``\\v``  vertical tab (ASCII 0x0B)
        * ``\\f``  form feed (ASCII 0x0C)
        * ``\\r``  carriage return (ASCII 0x0D)
        * ``\\e``  escape (ASCII 0x1B)

    Any other character preceded by backslash will appear in the output without the
    backslash (including backslash, single quote, and double quote).
    """

    _RE_QUOTE = re.compile(r"""(?P<end>["'])|\\(?P<esc>.)""")
    ESCAPES = {
        "0": "\0",
        "a": "\a",
        "b": "\b",
        "t": "\t",
        "n": "\n",
        "v": "\v",
        "f": "\f",
        "r": "\r",
        "e": "\x1b",
    }

    def __init__(self, name, value, pstate, no_prefix=False, no_add=False):
        if name is None:
            name = "[text (line %d #%d)]" % (
                pstate.line_no,
                pstate.implicit() if not no_add else -1,
            )
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
            raise ParseError(
                "Error parsing string, expected \" or ' at: %s%s" % (qchar, defn)
            )
        out, last = [], 0
        for match in TextSymbol._RE_QUOTE.finditer(defn):
            out.append(defn[last : match.start(0)])
            last = match.end(0)
            if match.group("end") == qchar:
                break
            elif match.group("end"):
                out.append(match.group("end"))
            else:
                out.append(
                    TextSymbol.ESCAPES.get(match.group("esc"), match.group("esc"))
                )
        else:
            raise ParseError("Unterminated string literal!")
        defn = defn[last:]
        sym = TextSymbol(None, "".join(out), pstate, no_add=no_add)
        return sym, defn


class _TextChoiceSymbol(_Symbol, SparseList):
    def __init__(self, name, pstate, no_prefix=False, no_add=False):
        if name is None:
            name = "[splist (line %d #%d)]" % (
                pstate.line_no,
                pstate.implicit() if not no_add else -1,
            )
        name = "%s.%s" % (pstate.prefix, name) if not no_prefix else name
        _Symbol.__init__(self, name, pstate, no_add=no_add)
        SparseList.__init__(self)
        self.can_terminate = True

    def generate(self, gstate):
        gstate.append(unichr_(self[random.randint(0, len(self) - 1)]))


def main(argv=None):

    logging.basicConfig(level=logging.INFO)
    if bool(os.getenv("DEBUG")):
        logging.getLogger().setLevel(logging.DEBUG)

    class _SafeFileType(argparse.FileType):
        def __call__(self, string):
            if string == "-":
                return argparse.FileType.__call__(self, string)
            if "w" in self._mode and os.path.isfile(string):
                raise argparse.ArgumentTypeError(
                    "output file exists, not overwriting: %s" % string
                )
            try:
                return io.open(string, mode=self._mode, encoding="utf-8")
            except IOError as exc:
                raise argparse.ArgumentTypeError("can't open '%s': %s" % (string, exc))

    argp = argparse.ArgumentParser(description="Generate a testcase from a grammar")
    argp.add_argument("input", type=_SafeFileType("r"), help="Input grammar definition")
    argp.add_argument(
        "output",
        type=_SafeFileType("w"),
        nargs="?",
        default=sys.stdout,
        help="Output testcase",
    )
    argp.add_argument(
        "-f",
        "--function",
        action="append",
        nargs=2,
        default=[],
        help="Function used in the grammar (eg. -f filter lambda x:x.replace('x','y')",
    )
    argp.add_argument(
        "-l",
        "--limit",
        type=int,
        default=DEFAULT_LIMIT,
        help="Set a generation limit (roughly)",
    )
    args = argp.parse_args(argv)
    args.function = {func: eval(defn) for (func, defn) in args.function}
    args.output.write(Grammar(args.input, limit=args.limit, **args.function).generate())


if __name__ == "__main__":
    main()
