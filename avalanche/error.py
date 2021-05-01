# coding=utf-8
# pylint: disable=missing-docstring
################################################################################
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

import inspect
import numbers

__all__ = ("GrammarException", "GenerationError", "IntegrityError", "ParseError")


class GrammarException(Exception):
    def __init__(self, *args, **kwds):
        super().__init__(*args, **kwds)
        self.raise_locals = inspect.currentframe().f_back.f_locals

    def __str__(self):
        pstate = self.raise_locals.get("pstate")
        gstate = self.raise_locals.get("gstate")
        raiser = self.raise_locals.get("self")
        line_no = None

        if len(self.args) == 2:
            self.args, arg = (self.args[0],), self.args[1]
            if not isinstance(arg, numbers.Number):
                raise RuntimeError(
                    "Bad argument type to GrammarException: %s" % type(arg).__name__
                )
            line_no = arg

        if not (pstate or gstate) and raiser:
            type_ = type(raiser).__name__
            if type_ == "_ParseState":
                pstate = raiser
            elif type_ == "_GenState":
                gstate = raiser
            elif line_no is None and hasattr(raiser, "line_no"):
                line_no = raiser.line_no

        if pstate and line_no is None:
            line_no = pstate.line_no

        msg = super().__str__()

        if pstate:
            extra = "("
            if pstate.name:
                extra += pstate.name + " "
            extra += "line %d)" % line_no

        elif gstate:
            extra = "(generation backtrace: %s)" % gstate.backtrace()

        elif line_no is not None:
            extra = "(line %d)"

        else:
            extra = None

        if msg and extra:
            return msg + " " + extra
        if extra:
            return extra
        return msg


class GenerationError(GrammarException):
    pass


class IntegrityError(GrammarException):
    pass


class ParseError(GrammarException):
    pass
