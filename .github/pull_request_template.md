<!--
Title: a Conventional Commit with a scope: the language or area (feat(cpp): …, fix(python): …, docs(github): …). It becomes the squash subject.
-->

## 🎯 At a glance

<!-- 2 to 3 sentences for someone who has not seen the diff: what changes and what it gives. -->

## 💡 Why

<!-- The need behind it. Link the issue it closes (Closes #N), or the specification's draft it follows. -->

## 🔧 What changes

<!-- A short list of the real changes, not a copy of the diff. -->
-

## 🧩 Languages and specification

<!-- The languages touched (C, C++, Python, TypeScript, Go, Rust, library, site, tools) and the specification's draft this follows, or "none". -->

## ✅ Checked

<!-- What was run beyond CI, and what could not be checked. CI already runs each language's own checks, REUSE and the link checks: no need to list them. -->

- [ ] A change of behaviour has its test in every language it concerns; a client fix also teaches `python/tools/hostile_server.py` its case
- [ ] Examples and tests use made-up games and names, and only reserved addresses (`example.org`, `192.0.2.0/24`)

Merge: squash
