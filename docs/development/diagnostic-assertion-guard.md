# Diagnostic assertion guard

`scripts/development/check-diagnostic-assertions.mjs` is developer tooling that refuses assertion
shapes whose **printed** value could carry captured subprocess stdout/stderr into a test log.
Tracking: [#253](https://github.com/Marcus-Levin/hylja/issues/253).

Node prints the compared actual and expected values itself when an `assert` call fails. A fixed assert
message therefore does not stop captured output reaching the log: it changes what the reader is told,
not what Node prints. This guard exists so the shape has to change *before* a failure prints the
capture, rather than after.

It is **not** Hylja runtime core, not a confidentiality guarantee and not an enforcement boundary.
`src/` imports nothing from here, it adds no dependency, it authenticates nobody and sends no bytes.
What it produces is a list of shapes to migrate, not a confirmed leak.

## Command

```sh
npm run check:diagnostic-assertions
```

The command takes an explicit path list. With no argument it checks the guarded list below. It also
runs inside `npm test` — `test/diagnostic-assertion-guard.test.mjs` asserts that every guarded file
carries zero findings — so CI catches it even without the dedicated step. The dedicated step exists so
the check is runnable and visible on its own.

## What it refuses

- a captured stream read, `run.stdout` or `run.stderr`, directly, through optional chaining, or
  through element access with that literal property name, and one element of a capture-derived
  container such as `lines[0]`;
- a simple local alias of one — a `const`/`let`/`var` binding whose initializer is such a read, or a
  destructured `{ stdout }` / `{ stderr: text }` — followed through chains of those bindings;
- a capture inside an object or array literal operand;
- a string built from one by a template literal, a `+` concatenation, or a call that is not a
  comparison, including `JSON.parse(captured.stdout)`.

It accepts the boolean and numeric comparisons that assert the same fact without printing the value:
`assert.equal(run.stderr === '', true, message)`, `assert.ok(!run.stderr, message)`,
`assert.equal(run.stdout.includes(planted), false, message)`, `assert.equal(lines.length, 2, ...)`.

## The guarded list

`GUARDED_TEST_FILES` currently names exactly one file: `test/hylja-native-lane.test.mjs`, which is
clean. The list is a named constant in the script, not a glob, so extending it is an explicit edit
visible in review.

**Residual surface, stated rather than implied.** Across `test/`, `src/`, `scripts/` and
`evaluations/` the guard reports 378 findings in 17 other files, most of which `npm test` and CI
already run. Extending the list is therefore a *migration*, not a configuration edit: the guard keeps
one flat binding map per file, so a single capture-derived binding taints every later assertion that
mentions it — `configured-units.test.mjs` alone reports 101 findings from one
`const result = JSON.parse(child.stdout)`. Scoping that map per function is the change that would make
list extension cheap. It is not done.

## Bounds

32 paths, 2 MiB per file, twelve alias hops, and 50 printed findings with the true count in the
summary line. Exceeding the first three is a fixed refusal (exit 2), never a silent pass. The
printed-findings bound truncates the listing but still states the true count, so it cannot read as
fewer findings either.

## What is outside it

Not taint analysis. A value that reaches an assertion through another function, a mutation, a renamed
binding, an exception's message, a file read or a non-assertion API passes silently, by design and in
the conservative direction — it can under-report, never over-report. Findings print only a location,
the assert method, the position class and the argument index: never source text, a value, or an
exception message.
